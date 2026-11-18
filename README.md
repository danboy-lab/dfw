# dfw

**Hardened `ufw` profile for bug-bounty laptops.** Outbound only, silent DROPs
("shadowblocks"), public abuse blocklists via `ipset`, and a loopback-only canary.

> Rode na máquina local, não por SSH. O `--baseline` reseta as regras atuais.

## O que faz

1. `deny incoming` / `allow outgoing` / `deny routed`, IPv6 on, loopback explícito.
2. Baixa listas públicas (Spamhaus DROP/EDROP, blocklist.de, IPsum), remove
   comentários, deduplica e **filtra faixas privadas/reservadas e a LAN**.
3. Carrega tudo num `ipset` `hash:net` chamado `bb-blocklist`.
4. Insere em `/etc/ufw/before.rules`:
   - `ufw-before-input` → `DROP` (pacote descartado sem resposta/ICMP);
   - `ufw-before-output` → `DROP` (evita saída para hosts maliciosos).
5. Instala `bb-ipset.service` para restaurar o set antes do `ufw` no boot.
6. `honeypot.py` escuta só em `127.0.0.1:8088` e loga conexões locais.

## Requisitos

- Arch Linux (usa `pacman` em `--install-deps`).
- `ufw`, `iptables`, `curl`, `ipset`.

## Uso

```bash
git clone https://github.com/danboy-lab/dfw.git
cd dfw

sudo bash ufw-hardened.sh --install-deps   # se ipset/curl faltarem
sudo bash ufw-hardened.sh --all
sudo bash ufw-hardened.sh --verify
```

Resultado esperado no `--verify`:

```
Status:                   active
Default:                  deny (incoming), allow (outgoing), deny (routed)
```

## Rollback

```bash
sudo bash ufw-hardened.sh --rollback
```

O script salva backups em `/tmp/bb-ufw-backup/<timestamp>/` antes de qualquer
mudança e restaura o estado anterior (incluindo se o ufw estava desligado).

## Canário local (honeypot)

Um honeypot externo exigiria abrir uma porta, o que quebra o perfil hardened.
Por isso este é local: detecta processos internos que tentem conectar na porta 8088.

```bash
mkdir -p ~/.config/systemd/user
cp bb-honeypot.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now bb-honeypot.service

python3 -c "import socket; socket.create_connection(('127.0.0.1',8088),1).close()"
tail -1 ~/Documents/bugbounty/honeypot/connections.log
```

## Limitações

- Blocklist é defesa em profundidade, não substitui `deny incoming`.
- Falso positivo: remova com `sudo ipset del bb-blocklist <IP/CIDR>`.
- Logs: `sudo ufw logging medium` temporariamente para investigar; depois volta ao `low`.
- Não mexe em Docker/ufw-docker nem em VPN com entrada (Tailscale/WireGuard).

## Fontes das listas

- https://www.spamhaus.org/drop/
- https://lists.blocklist.de/
- https://github.com/stamparm/ipsum
