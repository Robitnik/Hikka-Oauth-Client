from api import HikkaOAuthClient

# --------------------------
# Приклад використання (локальний сценарій)
# --------------------------
def example_usage():
    client = HikkaOAuthClient(
        client_reference="Твій Референс",
        client_secret="Твій Ключ",
    )

    # 1) Генеруємо URL згоди
    url = client.build_authorize_url(
        scopes=["read:user-details", "read:watchlist"],
    )
    print("Відкрий у браузері та авторизуйся:", url)

    # 2) Після згоди на твій redirect_uri прийде ?reference=...
    #    Для демо просто вставимо реальний redirect URL або сам reference:
    maybe_url_or_ref = input("Встав redirect URL або сам 'reference': ").strip()
    if maybe_url_or_ref.startswith("http"):
        reference = client.extract_reference_from_redirect(maybe_url_or_ref)
    else:
        reference = maybe_url_or_ref
    if not reference:
        raise RuntimeError("Не знайдено 'reference' у введених даних")

    token = client.exchange_request_reference(request_reference=reference)
    print("Отримали секрет:", token.secret)

    # 3) Читаємо профіль
    me = client.get_current_user(secret=token.secret)
    print("Поточний користувач:", me)

