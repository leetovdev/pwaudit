# pwaudit

![python](https://img.shields.io/badge/python-3.9%2B-black?style=flat-square)
![deps](https://img.shields.io/badge/dependencies-0-black?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)

Аудит паролей: оценка стойкости и проверка по базе утечек [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
(сотни миллионов скомпрометированных паролей). Пароль **никогда не уходит в сеть** — ни в открытом виде, ни целым хэшем.

```text
     #  password                  strength             leaks  notes
     1  1*****                    very weak      210 461 208  one of the most common passwords
     2  P*******                  very weak        6 421 042  one of the most common passwords
     3  Q**********               very weak              813  one of the most common passwords
     4  a*******                  weak                31 498  contains a year
     5  K*******                  fair                   321
     6  z*********                fair                     0  keyboard pattern like qwer
     7  c***********************  very strong            391
     8  v****************         very strong              0

  total 8   below strong: 6   breached: 6
```

Строка 7 — `correct horse battery staple`: по энтропии пароль отличный, но он есть в утечках.
Поэтому одной формулы стойкости мало, нужна и проверка по реальным базам.

## Как устроена проверка утечек

Используется модель **k-anonymity**:

1. Считается SHA-1 пароля: `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. На сервер отправляются только первые 5 символов: `5BAA6`
3. Сервер возвращает ~800 хэшей с таким началом, совпадение ищется локально
4. Включён `Add-Padding`, поэтому даже размер ответа не выдаёт, есть ли совпадение

## Что учитывает оценка стойкости

- энтропию по набору символов (латиница, кириллица, цифры, спецсимволы)
- топ самых частых паролей, включая варианты `P@ssw0rd`, `Password1!`, `qwerty2024`
- последовательности `abcd`, `123`, `987`
- раскладки клавиатуры `qwer`, `asdf`, `йцук` — в обе стороны
- повторы `aaa`, годы `1990`, «только цифры», длину меньше 8

Итог — шкала от `very weak` до `very strong`.

## Установка

```bash
git clone https://github.com/leetovdev/pwaudit
cd pwaudit
pip install .
```

## Использование

```bash
pwaudit
pwaudit -f passwords.txt
pwaudit -f passwords.txt --min-score 4
pwaudit -f passwords.txt --offline
pwaudit -g
pwaudit -g 32
```

| Режим | |
|---|---|
| без аргументов | интерактивно, ввод скрыт, ничего не сохраняется |
| `-f FILE` | массовый аудит списка (например, после выгрузки из своей системы) |
| `-g [LEN]` | генератор через `secrets` — криптостойкий ГСЧ |
| `--offline` | только оценка стойкости, без сети |
| `--min-score 0-4` | порог для `-f`, код выхода `1`, если кто-то ниже или в утечках |

## Тесты

```bash
python -m unittest -v
```

Сеть в тестах не используется — запросы к API замоканы, а заодно проверяется,
что в URL уходит только префикс хэша.

## Этика

Проверяйте только свои пароли или пароли своей организации в рамках аудита.
Файлы со списками паролей храните зашифрованными и удаляйте после проверки.

## Лицензия

MIT
