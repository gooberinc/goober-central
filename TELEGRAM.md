# Telegram Setup

## Step 1: Creating your bot

1. **Open Telegram**:
   Open the Telegram app on your phone or desktop.

2. **Search for the BotFather**:
   In the Telegram search bar, type **@BotFather** and select the official BotFather bot.

3. **Start a conversation with BotFather**:
   Press **Start** to begin a conversation with BotFather.

4. **Create a new bot**:
   Type the command `/newbot` and send it.

5. **Choose a name for your bot**:
   The BotFather will prompt you to choose a name for your bot (this is the display name).

6. **Choose a username for your bot**:
   The BotFather will ask for a username for your bot (this must be unique and end in "bot", like `your_bot`).

7. **Get your bot token**:
   After successfully creating the bot, BotFather will provide you with a token. It will look something like `123456789:ABCDefGhIjklmnOPQRstUvWxYZ`. Copy this token as you'll need it later.

## Step 2: Get Your Chat ID

1. **Search for the @userinfobot**:
   In the Telegram search bar, type **@userinfobot** and start a conversation with it.

2. **Grab your chat ID**:
   After starting the conversation, the bot will display your chat ID. Copy this ID and use it in your `.env` file.

## Step 3: Modifying the `.env` file.
    
1. Add the corresponding IDs to the entries. It should look something like this:
   ```bash
    telegram_token=123456789:ABCDefGhIjklmnOPQRstUvWxYZ
    telegram_id=1234567891011
    use_telegram=True

## Finalizing:

1. Save the `.env` file and start the server with uvicorn.
2. Get a Goober instance to ping the server.
3. Youre done!
