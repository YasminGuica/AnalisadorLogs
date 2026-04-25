"""
Analisador de Logs de Servidor
Autor: LogAnalyzer
Descrição: Analisa arquivos de log, gera estatísticas, relatórios e gráficos
"""

import re
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


class LogParser:
    """Responsável por fazer o parsing das linhas do log"""
    
    # Padrões regex para diferentes formatos de log
    PATTERNS = {
        'apache': re.compile(
            r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)'
        ),
        'simple': re.compile(
            r'(\d+\.\d+\.\d+\.\d+) - \[(.*?)\] "(.*?)" (\d{3})'
        )
    }
    
    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict]:
        """Tenta parsear uma linha usando os padrões disponíveis"""
        for log_type, pattern in cls.PATTERNS.items():
            match = pattern.search(line)
            if match:
                return cls._extract_data(match, log_type)
        return None
    
    @classmethod
    def _extract_data(cls, match, log_type: str) -> Dict:
        """Extrai os dados do match regex"""
        groups = match.groups()
        data = {
            'ip': groups[0],
            'timestamp': cls._clean_timestamp(groups[1]),
            'request': groups[2],
            'status': int(groups[3]),
        }
        
        # Adiciona tamanho se disponível
        if len(groups) > 4:
            data['size'] = int(groups[4])
        else:
            data['size'] = 0
            
        return data
    
    @staticmethod
    def _clean_timestamp(timestamp: str) -> str:
        """Remove timezone do timestamp"""
        return timestamp.split()[0] if ' ' in timestamp else timestamp
    
    @staticmethod
    def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
        """Converte string para datetime"""
        formats = [
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y:%H:%M:%S"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        return None


class LogAnalyzer:
    """Analisa os dados extraídos do log"""
    
    def __init__(self, logs: List[Dict]):
        self.logs = logs
        self._enrich_data()
    
    def _enrich_data(self):
        """Adiciona informações derivadas aos logs"""
        for log in self.logs:
            log['datetime'] = LogParser.parse_timestamp(log['timestamp'])
    
    @property
    def total_requests(self) -> int:
        return len(self.logs)
    
    @property
    def total_errors(self) -> int:
        return len([log for log in self.logs if log['status'] >= 400])
    
    @property
    def error_rate(self) -> float:
        return (self.total_errors / self.total_requests * 100) if self.total_requests else 0
    
    @property
    def unique_ips(self) -> int:
        return len(set(log['ip'] for log in self.logs))
    
    def get_top_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Retorna os IPs mais frequentes"""
        ip_counts = Counter(log['ip'] for log in self.logs)
        return ip_counts.most_common(limit)
    
    def get_top_endpoints(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Retorna os endpoints mais acessados"""
        endpoints = [log['request'].split()[1] for log in self.logs 
                    if ' ' in log['request']]
        return Counter(endpoints).most_common(limit)
    
    def get_errors_by_status(self) -> Dict[int, int]:
        """Retorna distribuição de erros por status code"""
        errors = [log['status'] for log in self.logs if log['status'] >= 400]
        return dict(Counter(errors))
    
    def get_traffic_by_hour(self) -> Dict[int, int]:
        """Retorna tráfego por hora"""
        hours = [log['datetime'].hour for log in self.logs 
                if log['datetime']]
        return dict(Counter(hours))
    
    def get_errors_by_hour(self) -> Dict[int, int]:
        """Retorna erros por hora"""
        hours = [log['datetime'].hour for log in self.logs 
                if log['datetime'] and log['status'] >= 400]
        return dict(Counter(hours))
    
    def get_peak_hour(self) -> Optional[Tuple[int, int]]:
        """Retorna a hora de pico (maior tráfego)"""
        traffic = self.get_traffic_by_hour()
        if traffic:
            return max(traffic.items(), key=lambda x: x[1])
        return None
    
    def get_summary(self) -> Dict:
        """Retorna resumo estatístico"""
        return {
            'total_requests': self.total_requests,
            'total_errors': self.total_errors,
            'error_rate': f"{self.error_rate:.2f}%",
            'unique_ips': self.unique_ips,
            'peak_hour': self.get_peak_hour()
        }


class ReportGenerator:
    """Gera relatórios em diferentes formatos"""
    
    def __init__(self, analyzer: LogAnalyzer, input_file: str):
        self.analyzer = analyzer
        self.input_file = input_file
    
    def generate_txt(self, output_file: str = "relatorio_logs.txt"):
        """Gera relatório em formato TXT"""
        with open(output_file, 'w', encoding='utf-8') as f:
            self._write_header(f)
            self._write_summary(f)
            self._write_top_ips(f)
            self._write_top_endpoints(f)
            self._write_error_distribution(f)
            self._write_traffic_by_hour(f)
        
        print(f"✅ Relatório TXT gerado: {output_file}")
    
    def generate_csv(self, output_file: str = "relatorio_logs.csv"):
        """Gera relatório em formato CSV"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow(['RELATÓRIO DE LOGS'])
            writer.writerow(['Arquivo', self.input_file])
            writer.writerow([])
            
            writer.writerow(['RESUMO', 'Valor'])
            for key, value in self.analyzer.get_summary().items():
                writer.writerow([key.replace('_', ' ').title(), value])
            writer.writerow([])
            
            writer.writerow(['TOP 10 IPs', 'Requisições'])
            for ip, count in self.analyzer.get_top_ips():
                writer.writerow([ip, count])
            writer.writerow([])
            
            writer.writerow(['Hora', 'Requisições'])
            for hour, count in sorted(self.analyzer.get_traffic_by_hour().items()):
                writer.writerow([f"{hour}:00", count])
        
        print(f"✅ Relatório CSV gerado: {output_file}")
    
    def _write_header(self, f):
        """Escreve cabeçalho do relatório"""
        f.write("=" * 70 + "\n")
        f.write("RELATÓRIO DE ANÁLISE DE LOGS\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Arquivo: {self.input_file}\n")
        f.write(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n")
    
    def _write_summary(self, f):
        """Escreve resumo estatístico"""
        f.write("-" * 70 + "\n")
        f.write("RESUMO ESTATÍSTICO\n")
        f.write("-" * 70 + "\n")
        
        summary = self.analyzer.get_summary()
        f.write(f"Total de requisições: {summary['total_requests']}\n")
        f.write(f"Total de erros: {summary['total_errors']}\n")
        f.write(f"Taxa de erro: {summary['error_rate']}\n")
        f.write(f"IPs únicos: {summary['unique_ips']}\n")
        
        if summary['peak_hour']:
            hour, count = summary['peak_hour']
            f.write(f"Horário de pico: {hour}:00 ({count} requisições)\n")
        f.write("\n")
    
    def _write_top_ips(self, f):
        """Escreve top IPs"""
        f.write("-" * 70 + "\n")
        f.write("TOP 10 IPs MAIS FREQUENTES\n")
        f.write("-" * 70 + "\n")
        
        for i, (ip, count) in enumerate(self.analyzer.get_top_ips(), 1):
            f.write(f"{i:2d}. {ip:15s} - {count:5d} requisições\n")
        f.write("\n")
    
    def _write_top_endpoints(self, f):
        """Escreve top endpoints"""
        f.write("-" * 70 + "\n")
        f.write("TOP 10 ENDPOINTS MAIS ACESSADOS\n")
        f.write("-" * 70 + "\n")
        
        for i, (endpoint, count) in enumerate(self.analyzer.get_top_endpoints(), 1):
            endpoint_short = endpoint[:60] + '...' if len(endpoint) > 60 else endpoint
            f.write(f"{i:2d}. {endpoint_short}\n")
            f.write(f"     {count} acessos\n")
        f.write("\n")
    
    def _write_error_distribution(self, f):
        """Escreve distribuição de erros"""
        f.write("-" * 70 + "\n")
        f.write("DISTRIBUIÇÃO DE ERROS\n")
        f.write("-" * 70 + "\n")
        
        errors = self.analyzer.get_errors_by_status()
        if errors:
            for status, count in sorted(errors.items()):
                f.write(f"HTTP {status}: {count} erros\n")
        else:
            f.write("Nenhum erro encontrado\n")
        f.write("\n")
    
    def _write_traffic_by_hour(self, f):
        """Escreve tráfego por hora"""
        f.write("-" * 70 + "\n")
        f.write("TRÁFEGO POR HORA\n")
        f.write("-" * 70 + "\n")
        
        traffic = self.analyzer.get_traffic_by_hour()
        for hour in range(24):
            count = traffic.get(hour, 0)
            bar = "█" * min(count // 5, 50)  # Gráfico de barras simples
            f.write(f"{hour:2d}:00 | {count:4d} {bar}\n")


class ChartGenerator:
    """Gera gráficos com matplotlib"""
    
    def __init__(self, analyzer: LogAnalyzer):
        self.analyzer = analyzer
    
    def generate(self, output_file: str = "analise_logs.png"):
        """Gera todos os gráficos"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Análise de Logs do Servidor', fontsize=14, fontweight='bold')
        
        self._plot_top_ips(axes[0, 0])
        self._plot_traffic_by_hour(axes[0, 1])
        self._plot_errors_by_hour(axes[1, 0])
        self._plot_error_distribution(axes[1, 1])
        
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"✅ Gráficos gerados: {output_file}")
    
    def _plot_top_ips(self, ax):
        """Gráfico de barras dos top IPs"""
        ips, counts = zip(*self.analyzer.get_top_ips(8))
        
        bars = ax.bar(range(len(ips)), counts, color='steelblue', alpha=0.7)
        ax.set_xlabel('IPs')
        ax.set_ylabel('Requisições')
        ax.set_title('Top 8 IPs Mais Frequentes')
        ax.set_xticks(range(len(ips)))
        ax.set_xticklabels(ips, rotation=45, ha='right', fontsize=8)
        
        # Adicionar valores nas barras
        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                   str(count), ha='center', va='bottom', fontsize=8)
    
    def _plot_traffic_by_hour(self, ax):
        """Gráfico de linha do tráfego por hora"""
        traffic = self.analyzer.get_traffic_by_hour()
        hours = list(range(24))
        values = [traffic.get(h, 0) for h in hours]
        
        ax.plot(hours, values, marker='o', color='green', linewidth=2, markersize=4)
        ax.fill_between(hours, values, alpha=0.3, color='green')
        ax.set_xlabel('Hora do Dia')
        ax.set_ylabel('Requisições')
        ax.set_title('Tráfego por Hora')
        ax.set_xticks(range(0, 24, 3))
        ax.grid(True, alpha=0.3)
        
        # Destacar pico
        max_hour = max(traffic, key=traffic.get) if traffic else None
        if max_hour:
            ax.axvline(x=max_hour, color='red', linestyle='--', alpha=0.5)
            ax.text(max_hour + 0.5, max(traffic.values()), f'Pico: {max_hour}:00',
                   fontsize=8, color='red')
    
    def _plot_errors_by_hour(self, ax):
        """Gráfico de barras dos erros por hora"""
        errors = self.analyzer.get_errors_by_hour()
        hours = list(range(24))
        values = [errors.get(h, 0) for h in hours]
        
        bars = ax.bar(hours, values, color='coral', alpha=0.7, width=0.8)
        ax.set_xlabel('Hora do Dia')
        ax.set_ylabel('Erros')
        ax.set_title('Erros por Hora')
        ax.set_xticks(range(0, 24, 3))
        ax.grid(True, alpha=0.3, axis='y')
        
        # Destacar horas com mais erros
        if errors:
            max_hour = max(errors, key=errors.get)
            bars[max_hour].set_color('red')
            bars[max_hour].set_alpha(0.9)
    
    def _plot_error_distribution(self, ax):
        """Gráfico de pizza da distribuição de erros"""
        errors = self.analyzer.get_errors_by_status()
        
        if not errors:
            ax.text(0.5, 0.5, 'Nenhum erro encontrado', 
                   ha='center', va='center', transform=ax.transAxes)
            ax.set_title('Distribuição de Erros')
            return
        
        labels = [f'HTTP {code}' for code in errors.keys()]
        sizes = list(errors.values())
        colors = plt.cm.Set3(range(len(errors)))
        
        wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%',
                                          colors=colors, startangle=90)
        ax.set_title('Distribuição por Tipo de Erro')
        
        # Ajustar tamanho da fonte
        for text in texts:
            text.set_fontsize(9)
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')


class LogProcessor:
    """Orquestra todo o processo de análise"""
    
    def __init__(self, log_file: str):
        self.log_file = Path(log_file)
        self.raw_logs = []
        
    def load(self) -> bool:
        """Carrega e processa o arquivo de log"""
        if not self.log_file.exists():
            print(f"❌ Arquivo não encontrado: {self.log_file}")
            return False
        
        print(f"📂 Lendo arquivo: {self.log_file}")
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                log_entry = LogParser.parse_line(line.strip())
                if log_entry:
                    self.raw_logs.append(log_entry)
        
        print(f"✅ {len(self.raw_logs)} linhas processadas")
        return True
    
    def analyze(self):
        """Executa a análise completa"""
        if not self.raw_logs:
            print("❌ Nenhum dado para analisar")
            return
        
        analyzer = LogAnalyzer(self.raw_logs)
        
        # Mostrar resumo no console
        self._print_console_summary(analyzer)
        
        # Gerar relatórios
        report_gen = ReportGenerator(analyzer, str(self.log_file))
        report_gen.generate_txt()
        report_gen.generate_csv()
        
        # Gerar gráficos
        chart_gen = ChartGenerator(analyzer)
        chart_gen.generate()
        
        print("\n✨ Análise concluída com sucesso!")
    
    def _print_console_summary(self, analyzer: LogAnalyzer):
        """Imprime resumo no console"""
        print("\n" + "=" * 50)
        print("📊 RESULTADOS DA ANÁLISE")
        print("=" * 50)
        
        summary = analyzer.get_summary()
        print(f"Total de requisições: {summary['total_requests']}")
        print(f"Total de erros: {summary['total_errors']}")
        print(f"Taxa de erro: {summary['error_rate']}")
        print(f"IPs únicos: {summary['unique_ips']}")
        
        if summary['peak_hour']:
            hour, count = summary['peak_hour']
            print(f"Horário de pico: {hour}:00 ({count} requisições)")
        
        print("\n🔝 Top 5 IPs:")
        for i, (ip, count) in enumerate(analyzer.get_top_ips(5), 1):
            print(f"  {i}. {ip}: {count} req")


def create_sample_log(filename: str = "sample_access.log"):
    """Cria um arquivo de log de exemplo para demonstração"""
    sample_data = [
        '192.168.1.100 - - [10/Jan/2024:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.101 - - [10/Jan/2024:10:16:45 +0000] "GET /about.html HTTP/1.1" 200 2345',
        '192.168.1.100 - - [10/Jan/2024:10:17:12 +0000] "POST /api/login HTTP/1.1" 401 567',
        '192.168.1.102 - - [10/Jan/2024:10:18:03 +0000] "GET /products HTTP/1.1" 200 3456',
        '192.168.1.103 - - [10/Jan/2024:10:19:22 +0000] "GET /index.html HTTP/1.1" 404 890',
        '192.168.1.100 - - [10/Jan/2024:13:25:11 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.104 - - [10/Jan/2024:13:26:45 +0000] "GET /images/logo.png HTTP/1.1" 200 4567',
        '192.168.1.101 - - [10/Jan/2024:13:30:21 +0000] "POST /api/login HTTP/1.1" 200 456',
        '192.168.1.103 - - [10/Jan/2024:14:15:33 +0000] "GET /admin/dashboard HTTP/1.1" 403 234',
        '192.168.1.101 - - [10/Jan/2024:14:19:11 +0000] "GET /api/data HTTP/1.1" 500 123',
        '192.168.1.100 - - [10/Jan/2024:15:21:44 +0000] "GET /products HTTP/1.1" 200 3456',
        '192.168.1.108 - - [10/Jan/2024:15:22:55 +0000] "GET /about.html HTTP/1.1" 200 2345',
        '192.168.1.103 - - [10/Jan/2024:15:24:33 +0000] "GET /css/style.css HTTP/1.1" 404 567',
        '192.168.1.100 - - [10/Jan/2024:16:25:44 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.109 - - [10/Jan/2024:16:26:55 +0000] "GET /products HTTP/1.1" 200 3456',
    ]
    
    with open(filename, 'w') as f:
        f.write('\n'.join(sample_data))
    
    print(f"📝 Arquivo de exemplo criado: {filename}")
    return filename


def main():
    """Função principal"""
    print("🚀 LogAnalyzer - Analisador de Logs de Servidor")
    print("-" * 50)
    
    # Criar arquivo de exemplo
    sample_file = create_sample_log()
    
    # Processar e analisar
    processor = LogProcessor(sample_file)
    
    if processor.load():
        processor.analyze()
    else:
        print("❌ Falha ao processar o arquivo")


if __name__ == "__main__":
    main()