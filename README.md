# passcoder

Доступна работа в трех режимах:

reg - регистрация пользователя.

В результате программа создает папку по логину пользователя, которая содержит в себе открытый ключ и закрытый ключем, зашифрованным на AES, дополнительным паролем.

enc - шифрование пароля.

На вход программа запрашивает путь к файлу с открытым ключом и просит ввести пароль.
В результате программа выводит пароль, зашифрованный на открытом ключе пользователя криптосистемой Рабина

dec - дешифрование файла

На вход программа запрашивает путь к файлу с секретным ключом и шифр-текст пароля в кодировке base32. 
На выходе программа выводит на экран пароль
