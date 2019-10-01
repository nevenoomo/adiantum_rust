# Adiantum rust implementation
## Зависимости
Для запуска потребуется система сборки [cargo](https://rurust.github.io/cargo-docs-ru/), которая устанавливается вместе с пакетом [rustup](https://www.rust-lang.org/tools/install).
Также весь инструментарий rust доступен в виде [docker контейнера](https://hub.docker.com/_/rust) 

## Chacha20
### Сборка и запуск
Запуск производится командой:
```sh
cargo run --bin chacha20 --release <args>
```