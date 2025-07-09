#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.util import quietRun
from time import sleep
import random
import sys
import os
import atexit

# Configuración global ajustada para prueba
TEST_DURATION = 300  # 5 minutos
TRAFFIC_TYPES = ["normal", "attack", "mixed", "cli"]
ATTACK_TYPES = ["syn", "udp", "icmp", "http", "mixed"]
DEFAULT_TYPE = "mixed"
SERVER_PORTS = [5001, 5002, 80]
SWITCH_STARTUP_DELAY = 2  # Reducido para prueba más rápida
NUM_NORMAL_HOSTS = 3      # Solo 3 hosts normales
NUM_ATTACKERS = 1         # Solo 1 atacante

def clean_system():
    """Limpia todas las interfaces y procesos residuales"""
    info('*** Limpiando sistema\n')
    for i in range(1, 6):
        for j in range(1, 5):
            quietRun(f'ip link del s{i}-eth{j} 2>/dev/null')
    quietRun('ip -all netns del 2>/dev/null')
    quietRun('mn -c 2>/dev/null')
    for i in range(1, 6):
        quietRun(f'ovs-vsctl --if-exists del-br s{i}')

class AdvancedTopo(Topo):
    def __init__(self, **opts):
        clean_system()
        self.host_ips = {}
        self.server_hosts = [5, 7, 9, 11, 13]
        Topo.__init__(self, **opts)

    def build(self):
        info('*** Creando topología\n')
        
        # Crear switches
        switches = []
        for i in range(1, 6):
            switch = self.addSwitch(f's{i}', protocols='OpenFlow13')
            switches.append(switch)
            sleep(SWITCH_STARTUP_DELAY)
        
        # Conectar switches
        self.addLink(switches[0], switches[1], cls=TCLink, bw=20, delay='1ms', loss=0)
        self.addLink(switches[0], switches[2], cls=TCLink, bw=20, delay='1ms', loss=0)
        self.addLink(switches[1], switches[3], cls=TCLink, bw=15, delay='2ms', loss=0)
        self.addLink(switches[2], switches[4], cls=TCLink, bw=15, delay='2ms', loss=0)
        
        # Configurar hosts
        for i in range(1, 14):
            ip = f'10.1.1.{i}'
            host_name = f'h{i}'
            h = self.addHost(host_name, ip=ip+'/24',
                           mac=f"00:00:00:00:00:{i:02x}",
                           defaultRoute="via 10.1.1.254")
            
            if i <= 5:
                self.addLink(h, switches[0], cls=TCLink, bw=10, delay='1ms', loss=0)
            elif i <= 7:
                self.addLink(h, switches[1], cls=TCLink, bw=10, delay='1ms', loss=0)
            elif i <= 9:
                self.addLink(h, switches[2], cls=TCLink, bw=10, delay='1ms', loss=0)
            elif i <= 11:
                self.addLink(h, switches[3], cls=TCLink, bw=10, delay='1ms', loss=0)
            else:
                self.addLink(h, switches[4], cls=TCLink, bw=10, delay='1ms', loss=0)
            
            self.host_ips[host_name] = ip
            sleep(0.2)  # Retardo reducido

def main():
    setLogLevel('info')
    clean_system()
    
    try:
        # Configurar parámetros
        test_type = DEFAULT_TYPE
        if len(sys.argv) > 1 and sys.argv[1] in TRAFFIC_TYPES:
            test_type = sys.argv[1]
        else:
            error(f"*** Error: Tipo de prueba '{sys.argv[1] if len(sys.argv) > 1 else ''}' no válido. Usar: {TRAFFIC_TYPES}\n")
            sys.exit(1)
        
        duration = TEST_DURATION
        if len(sys.argv) > 2 and sys.argv[2].isdigit():
            duration = int(sys.argv[2])
        
        attack_type = "mixed"
        if len(sys.argv) > 3 and sys.argv[3] in ATTACK_TYPES:
            attack_type = sys.argv[3]
        
        # Crear red
        topo = AdvancedTopo()
        c1 = RemoteController('c1', ip='127.0.0.1', port=6653)
        net = Mininet(topo=topo, controller=c1, link=TCLink,
                     autoSetMacs=True, cleanup=True, waitConnected=True)
        
        # Iniciar red
        net.start()
        sleep(5)  # Espera reducida
        
        # Verificar conexión de switches
        for switch in net.switches:
            info(f"*** Switch {switch.name} {'conectado' if switch.connected() else 'NO CONECTADO'}\n")
            if not switch.connected():
                error(f"*** Error: Switch {switch.name} no se conectó al controlador\n")
        
        if test_type == "cli":
            CLI(net)
        else:
            # Iniciar servicios en servidores
            info('*** Iniciando servicios en servidores\n')
            for host_num in topo.server_hosts:
                h = net.get(f'h{host_num}')
                h.cmd(f'iperf -s -p {SERVER_PORTS[0]} > /tmp/iperf_tcp_{host_num}.log &')
                h.cmd(f'iperf -u -s -p {SERVER_PORTS[1]} > /tmp/iperf_udp_{host_num}.log &')
                h.cmd(f'python3 -m http.server {SERVER_PORTS[2]} > /tmp/web_{host_num}.log 2>&1 &')
                sleep(0.5)
            
            # Manejar ataques según tipo de prueba
            attackers = [1, 2, 6, 8]
            num_attackers = 0

            if test_type == "attack":
                num_attackers = min(NUM_ATTACKERS, len(attackers))
                info(f'*** Iniciando {num_attackers} atacantes (tipo: {attack_type})\n')
            elif test_type == "mixed":
                num_attackers = min(NUM_ATTACKERS, len(attackers))
                info(f'*** Iniciando {num_attackers} atacantes (modo mixto)\n')
            else:
                info('*** Modo normal: no se inician atacantes\n')

            if num_attackers > 0:
                for attacker in attackers[:num_attackers]:
                    info(f'*** Iniciando ataque en h{attacker}\n')
                    if attack_type == "mixed":
                        net.get(f'h{attacker}').cmd(f'bash attack.sh > /tmp/attack_{attacker}.log &')
                    else:
                        net.get(f'h{attacker}').cmd(f'bash attack.sh 10.1.1.{random.choice(topo.server_hosts)} {attack_type} > /tmp/attack_{attacker}.log &')
                    sleep(0.5)
            
            # Generar tráfico normal en hosts no atacantes
            normal_hosts = [h for h in range(1, 14) if h not in attackers[:num_attackers]]
            for host in normal_hosts[:NUM_NORMAL_HOSTS]:
                net.get(f'h{host}').cmd(f'bash normal.sh > /tmp/normal_{host}.log &')
            
            # Esperar y monitorear
            info(f'*** Simulación iniciada (Duración: {duration} segundos)\n')
            for remaining in range(duration, 0, -10):
                info(f'*** Tiempo restante: {remaining}s\n')
                sleep(10)
            
    except Exception as e:
        error(f'*** Error: {str(e)}\n')
    finally:
        info('*** Finalizando\n')
        if 'net' in locals():
            net.stop()
        clean_system()

if __name__ == '__main__':
    main()