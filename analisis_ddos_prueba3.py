#!/usr/bin/python3
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt

def analyze_detection_performance():
    # Cargar logs
    attacks = pd.read_csv('/tmp/ddos_attack.log', sep='|', parse_dates=['timestamp'])
    detections = pd.read_csv('/tmp/ddos_detection_logs/detection_events.log', 
                           sep='|', parse_dates=['timestamp'])
    
    # Procesar eventos de ataque
    attack_events = attacks[attacks['event_type'].str.contains('ATTACK_')]
    attack_periods = []
    current_attack = None
    
    for _, row in attack_events.iterrows():
        if 'START' in row['event_type']:
            current_attack = {
                'type': row['attack_type'],
                'target': row['target'],
                'start': row['timestamp'],
                'end': None
            }
        elif current_attack and 'END' in row['event_type']:
            current_attack['end'] = row['timestamp']
            attack_periods.append(current_attack)
            current_attack = None
    
    # Procesar detecciones
    detection_events = detections[detections['event_type'].str.contains('ATTACK_')]
    
    # Evaluar cada ataque
    results = []
    for attack in attack_periods:
        detected = detection_events[
            (detection_events['timestamp'] >= attack['start']) & 
            (detection_events['timestamp'] <= attack['end'] + pd.Timedelta(seconds=30))
        ].any().any()
        
        results.append({
            'attack_type': attack['type'],
            'target': attack['target'],
            'start_time': attack['start'],
            'duration': (attack['end'] - attack['start']).total_seconds(),
            'detected': detected,
            'detection_time': None
        })
    
    # Calcular métricas
    total_attacks = len(results)
    detected_attacks = sum(1 for r in results if r['detected'])
    detection_rate = (detected_attacks / total_attacks) * 100 if total_attacks > 0 else 0
    
    # Generar reporte
    print("\n=== Reporte de Detección de DDoS ===")
    print(f"Total de ataques generados: {total_attacks}")
    print(f"Ataques detectados: {detected_attacks}")
    print(f"Tasa de detección: {detection_rate:.2f}%")
    
    # Generar gráfico
    if total_attacks > 0:
        attack_types = pd.DataFrame(results)['attack_type'].value_counts()
        detection_rates = {}
        
        for atype in attack_types.index:
            type_attacks = [r for r in results if r['attack_type'] == atype]
            type_detected = sum(1 for r in type_attacks if r['detected'])
            detection_rates[atype] = (type_detected / len(type_attacks)) * 100
        
        plt.figure(figsize=(10, 5))
        plt.bar(detection_rates.keys(), detection_rates.values())
        plt.title('Tasa de Detección por Tipo de Ataque')
        plt.ylabel('Porcentaje de Detección')
        plt.ylim(0, 100)
        plt.savefig('/tmp/ddos_detection_rates.png')
        print("\nGráfico generado en /tmp/ddos_detection_rates.png")

if __name__ == '__main__':
    analyze_detection_performance()