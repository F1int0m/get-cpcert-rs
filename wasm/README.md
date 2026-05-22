# get-cpcert-wasm

WebAssembly-обёртка над `get-cpcert`. Позволяет извлекать сертификат и ключ из контейнера КриптоПро прямо в браузере — без отправки файлов на сервер.

## Сборка

```bash
# Установите wasm-pack один раз:
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Соберите из корня репозитория:
wasm-pack build wasm --target web --release

# Соберётся каталог wasm/pkg/ с .wasm + .js + .d.ts.
```

## Демонстрация в браузере

```bash
cp -r wasm/pkg wasm/demo/pkg
python3 -m http.server -d wasm/demo 8000
# открыть http://localhost:8000
```

Загрузите `header.key`, `primary.key`, `masks.key`, введите пароль (если есть) — и нажмите «Извлечь PEM». Можно тут же скачать результирующий `.pem`.

## API

```ts
// extract_pem(header, primary, masks, password) -> string
function extract_pem(
  header: Uint8Array,
  primary: Uint8Array,
  masks: Uint8Array,
  password: string,
): string;
```

Бросает строковое исключение JS при ошибке (неверный пароль → строка содержит `Invalid password`).
