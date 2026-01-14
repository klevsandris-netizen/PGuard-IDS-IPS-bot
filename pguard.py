import os
import threading
import asyncio
import time
from datetime import datetime
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, BufferedInputFile
from scapy.all import sniff, IP, TCP

import componentsofapp.keyboardMarkUpik as KbMP 
import databaseiu as db

# --- data ---
load_dotenv("data.env")
TOKEN = os.getenv("BOT_TOKENPG")
ADMIN_ID = int(os.getenv("USERS_ID"))
LOG_FILE = "ponchoguard_events.log"

bot = Bot(token=TOKEN)
dp = Dispatcher()



MONITOR_ON = True
TARGET_PORTS = [22, 80, 21, 3389]
last_alerts = {} 
ALERT_INTERVAL = 60

# --- Def) ---

def write_log(ip, message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] IP: {ip} | {message}\n")

def apply_ban(ip):
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(cmd)
    return cmd

# --- Handlers ---

@dp.message(Command("start"))
async def welmessagemiau(message: types.Message):
    
    user_id = message.from_user.id
    username = message.from_user.username or "Non_Grata_Person"
    db.register_user(user_id, username)
    
    if user_id == ADMIN_ID:
       
        await message.answer(
            "🪇⚔️**PonchoGuard**🪇⚔️\n\n"
            "Приветствую,**{first_name}**!😈\n"
            "Готов защищать ваши данные!;)",
            reply_markup=KbMP.PG_menu, 
            parse_mode="Markdown"
        )

@dp.message(Command("status"))
async def status_check(message: types.Message):
    if message.from_user.id == ADMIN_ID:
        state = "✅ РАБОТАЕТ" if MONITOR_ON else "🛑 ВЫКЛЮЧЕН"
        await message.reply(f"📊 **Статус:** {state}\n🛡️ **Порты:** `{TARGET_PORTS}`", parse_mode="Markdown")

        

@dp.message(Command("help"))
async def help_manual(message: types.Message):
    help_text = (
    "**Вас приветствует справочник сетевого защитника PonchoGuard! 😈** \n\n"
    "**Основные Функции:**\n"
    "/start - Запуск бота и вывод главного меню.\n"
    "/status - работает сейчас защита или нет.\n"
    "/logs - Выгрузить историю атак и очистить файл.\n"
    "/help - Этот справочник.\n\n"
    "**/donate - помочь проекту чем не жалко(если есть возможность и хотите,спс) ;)**\n"
    "❗**ЕСЛИ ЗАБЛОКАЛ СЕБЯ ИЛИ ДРУГА:**\n"
    "Если ты случайно нажал BAN и доступ пропал, введи в терминале Linux:\n\n"
    " **Разбанить конкретный IP:**\n"
    "`sudo iptables -D INPUT -s IP_АДРЕС -j DROP`\n\n"
    "❗❗❗**РАЗБАНИТЬ ВСЕХ (полный сброс):**\n"
    "`sudo iptables -F` — используй это, если всё упало!\n\n"
    "📋 **Посмотреть список всех банов:**\n"
    "`sudo iptables -L --line-numbers`"
    )
    await message.reply(help_text, parse_mode="Markdown")

@dp.message(Command("logs"))
async def send_history(message: types.Message):
    if message.from_user.id == ADMIN_ID:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🗑️ Очистить логи", callback_data="clear_logs_confirm")]
            ])
            with open(LOG_FILE, "rb") as f:
                file_data = f.read()
                input_file = BufferedInputFile(file_data, filename="poncho_logs.txt")
                await message.answer_document(document=input_file, caption="📂 Твои логи атак:", reply_markup=kb)
        else:
            await message.answer("📭 Файл логов пуст или еще не создан.")

# --- Callbacks ---

@dp.callback_query(F.data == "clear_logs_confirm")
async def clear_logs(callback: types.CallbackQuery):
    with open(LOG_FILE, "w") as f:
        f.write(f"--- Log cleared at {datetime.now()} ---\n")
    await callback.message.edit_caption(caption="✅ Логи очищены!")
    await callback.answer()

@dp.callback_query(F.data.startswith('block_'))
async def block_button(callback: types.CallbackQuery):
    ip_to_block = callback.data.replace('block_', '')
    apply_ban(ip_to_block)
    write_log(ip_to_block, "USER_BANNED_IP")
    await bot.send_message(ADMIN_ID, f"🚫 **Бан выдан!**\nIP: `{ip_to_block}`")
    await callback.answer()

@dp.callback_query(F.data == 'skip')
async def skip_button(callback: types.CallbackQuery):
    await bot.send_message(ADMIN_ID, "⚠️ Атака проигнорирована.")
    await callback.answer()

# --- Network ---

def network_monitor(loop):
    def process_packet(pkt):
        global MONITOR_ON
        if not MONITOR_ON: return

        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            attacker_ip = pkt[IP].src
            target_port = pkt[TCP].dport
            
            if target_port in TARGET_PORTS:
                curr_time = time.time()
                if (attacker_ip, target_port) in last_alerts:
                    if curr_time - last_alerts[(attacker_ip, target_port)] < ALERT_INTERVAL:
                        return
                
                last_alerts[(attacker_ip, target_port)] = curr_time
                write_log(attacker_ip, f"Activity on port {target_port}")
                
                kb = InlineKeyboardMarkup(inline_keyboard=[
                    [
                        InlineKeyboardButton(text=f"🚫 BAN {attacker_ip}", callback_data=f"block_{attacker_ip}"),
                        InlineKeyboardButton(text="⏭️ Игнор", callback_data="skip")
                    ]
                ])
                
                msg = (f"🚨 **PonchoGuard Alert!**\n"
                       f"Стук в порт: `{target_port}`\n"
                       f"IP: `{attacker_ip}`")
                
                asyncio.run_coroutine_threadsafe(
                    bot.send_message(ADMIN_ID, msg, reply_markup=kb, parse_mode="Markdown"),
                    loop
                )

    print("[*] PonchoGuard: сканируем пакеты...")
    sniff(filter="tcp", prn=process_packet, store=0)

async def main():
    
    db.init_db() #database)

    loop = asyncio.get_running_loop()
    threading.Thread(target=network_monitor, args=(loop,), daemon=True).start()
    print("[!] PonchoGuard запущен.")
    await dp.start_polling(bot)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Выход...")