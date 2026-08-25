# Ansible deployment

Playbook собирает `../src` на контроллере, затем последовательно обновляет обе
backend VM. Адреса читаются из текущего Terraform state, поэтому динамический
inventory не содержит жёстко заданных IP.

На VM устанавливается один статический Go-бинарник и hardened systemd unit:

- сервис работает от непривилегированного пользователя `sws-lab`;
- единственная capability — `CAP_NET_BIND_SERVICE` для порта `80`;
- `TRUST_PROXY_HEADERS=true`, поскольку вход на `80` ограничен `backend-sg` и
  разрешён только от `alb-sg`;
- хосты обновляются по одному, после каждого обновления проверяется `/healthz`;
- в конце с backend A проверяется путь через публичный HTTP listener ALB на
  порту `80`;

## Подготовка

Нужны Python 3, Go 1.23+ и Terraform state в `../terraform`. По умолчанию
playbook использует локальный ключ без passphrase `.keys/ansible_ed25519`.
Каталог `.keys/` исключён из Git; публичная часть хранится в
`../terraform/files/ssh/ansible-deploy.pub` и устанавливается через cloud-init.

```bash
cd ansible
make bootstrap
make syntax-check
```

## Deployment

Запуск:

```bash
make deploy
```

При первом подключении используется `StrictHostKeyChecking=accept-new`: новый
ключ хоста сохраняется, но изменившийся ключ по-прежнему отклоняется.

При необходимости можно отключить только финальную проверку ALB; локальные
`/healthz` на обеих VM останутся обязательными:

```bash
make deploy ANSIBLE_ARGS='-e sws_lab_verify_alb=false'
```

Логи и состояние сервиса:

```bash
../terraform/.tools/bin/terraform -chdir=../terraform output ssh_commands
ssh grauwolf@<vm-a-ip> sudo systemctl status sws-lab
ssh grauwolf@<vm-b-ip> sudo journalctl -u sws-lab -f
```
