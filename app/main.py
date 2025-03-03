import redis
import json
from datetime import datetime

# Conectar ao Redis (será configurado no Kubernetes)
r = redis.Redis(host='redis-service', port=6379, db=0)

# Função para armazenar log no Redis
def store_log(ip, event_type):
    log = {
        'ip': ip,
        'event_type': event_type,
        'timestamp': str(datetime.now())
    }
    r.lpush('security_logs', json.dumps(log))  # Adiciona log a uma lista no Redis
    print(f"Log armazenado: {log}")

# Função para analisar logs e procurar falhas de login
def analyze_logs():
    logs = r.lrange('security_logs', 0, -1)  # Pega todos os logs armazenados
    ip_attempts = {}

    for log in logs:
        log_data = json.loads(log)
        ip = log_data['ip']
        event = log_data['event_type']
        
        if event == "failed_login":
            ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

    print("Análise de falhas de login:")
    for ip, attempts in ip_attempts.items():
        if attempts > 3:
            print(f"Alerta! IP: {ip} tentou logar {attempts} vezes com falha!")

# Função principal
def main():
    # Exemplo de recebimento de logs
    store_log('192.168.1.100', 'failed_login')
    store_log('192.168.1.101', 'failed_login')
    store_log('192.168.1.100', 'failed_login')
    store_log('192.168.1.100', 'failed_login')
    store_log('192.168.1.102', 'successful_login')

    # Analisar logs
    analyze_logs()

if __name__ == "__main__":
    main()

