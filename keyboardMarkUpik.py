from aiogram.types import ReplyKeyboardMarkup , KeyboardButton

PG_menu = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="/status"), KeyboardButton(text="/help")], 
        [KeyboardButton(text="/logs")] , KeyboardButton(text = "/donate")                                
    ],
    resize_keyboard=True,           
    input_field_placeholder="Чем могу вам помочь?" 
)
