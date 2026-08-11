# Identity Service

> [!NOTE]
> Project is under development.
>
> <img src="https://raw.githubusercontent.com/MariaLetta/free-gophers-pack/9bb81600dd2a9ac5a68799f9a57f02f7369c4c4e/characters/svg/42.svg" width="125" alt="Gopher mascot">

## About

A simple identity management microservice.

It provides passwordless authentication via OTP codes
and manages access and refresh tokens (JWTs).

You can review the REST API endpoints in the [API documentation](./API.md).

## Running

Clone the repository and run the example:

```bash
git clone https://github.com/carafie/identity.git
cd identity
docker compose -f example.compose.yml up -d
```

Outgoing emails are logged to stdout, as the example uses `MAILER=log`.
Review `example.env` file for all available options.

## Disclaimer

This is a personal side project built for learning and experimentation; it is provided as-is and is not intended for production use.

## License

Licensed under the [MIT License](./LICENSE).
