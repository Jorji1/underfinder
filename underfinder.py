import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from requests.sessions import Session
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote_plus
from bs4 import BeautifulSoup
import collections 



USER_AGENT = "underfinder | V1" 


COMMON_FILES_DIRS = [
    "robots.txt", ".htaccess", ".env", "config.php", "wp-config.php",
    "config/database.yml", "WEB-INF/web.xml", "backup/", "admin/", "login/",
    "phpmyadmin/", ".git/config", "Dockerfile", "docker-compose.yml",
    "README.md", "CHANGELOG.md", "error_log", "access_log"
]
SECURITY_HEADERS_CHECK = {
    "X-Frame-Options": ["DENY", "SAMEORIGIN"], "Content-Security-Policy": None,
    "Strict-Transport-Security": None, "X-Content-Type-Options": ["nosniff"],
    "Referrer-Policy": ["no-referrer", "same-origin", "strict-origin-when-cross-origin"],
    "Permissions-Policy": None, "Server": None, "X-Powered-By": None
}
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax", "warning: mysql_fetch",
    "unclosed quotation mark", "supplied argument is not a valid mysql",
    "ora-01756", "syntax error near", "incorrect syntax near",
    "conversion failed when converting the varchar value", "pg_query()", "pg_execute()"
]
XSS_PAYLOADS = [
    "<script>alert('XSS_TEST_BY_SCANNER_V1.2_SPIDER')</script>",
    "<img src=x onerror=alert('XSS_TEST_IMG_V1.2_SPIDER')>",
]
SQLI_PAYLOADS = {
    "basic_apostrophe": "'", "basic_quote": "\"", "comment_sqli": "' ;--",
    "union_sqli_lite": "' UNION SELECT null--", "always_true": "' OR '1'='1"
}


MAX_URLS_TO_SCAN = 20000

def log_message(results_widget, message):
 
    if results_widget.winfo_exists():
        results_widget.insert(tk.END, message)
        results_widget.see(tk.END)
        results_widget.update_idletasks()


def check_connectivity(target_url, results_widget, session):
   
    log_message(results_widget, f"[INFO] Verificando conectividade com {target_url}...\n")
    headers = {'User-Agent': USER_AGENT}
    try:
        response = session.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        log_message(results_widget, f"[+] Conectado com sucesso! Status: {response.status_code}\n")
        if response.url != target_url:
            log_message(results_widget, f"[INFO] URL final após redirecionamentos: {response.url}\n")
        return response
    except requests.exceptions.HTTPError as e:
        log_message(results_widget, f"[-] Erro HTTP: {e}. Status: {e.response.status_code}\n")
    except requests.exceptions.ConnectionError as e:
        log_message(results_widget, f"[-] Erro de Conexão: {e}\n")
    except requests.exceptions.Timeout:
        log_message(results_widget, "[-] Timeout: O pedido demorou demasiado a responder.\n")
    except requests.exceptions.RequestException as e:
        log_message(results_widget, f"[-] Erro no pedido: {e}\n")
    return None

def scan_common_files(base_url, results_widget, session):
  
    log_message(results_widget, "\n--- Verificando ficheiros/diretórios comuns ---\n")
    headers = {'User-Agent': USER_AGENT}
    found_any = False
    for item in COMMON_FILES_DIRS:
        test_url = urljoin(base_url, item)
        log_message(results_widget, f"[INFO] Testando: {test_url}...")
        try:
            response = session.get(test_url, headers=headers, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                log_message(results_widget, f" [ALERTA] Encontrado (200 OK): {test_url}\n")
                found_any = True
            elif response.status_code == 403:
                log_message(results_widget, f" [INFO] Potencialmente existe mas proibido (403 Forbidden): {test_url}\n")
                found_any = True
            else:
                log_message(results_widget, f" [NÃO ENCONTRADO ({response.status_code})]\n")
        except requests.exceptions.RequestException:
            log_message(results_widget, f" [ERRO AO ACEDER]\n")
    if not found_any:
        log_message(results_widget, "[INFO] Nenhum ficheiro/diretório comum da lista foi encontrado com status 200 ou 403.\n")


def analyze_headers(response, results_widget):
   
    log_message(results_widget, "\n--- Analisando Cabeçalhos HTTP ---\n")
    headers_data = response.headers
    for header_name, ideal_values in SECURITY_HEADERS_CHECK.items():
        actual_value = headers_data.get(header_name)
        if actual_value:
            log_message(results_widget, f"[INFO] Cabeçalho '{header_name}': {actual_value}\n")
            if header_name in ["Server", "X-Powered-By"]:
                log_message(results_widget, f"    -> [ALERTA] Exposição de informação. Considere remover ou ofuscar.\n")
            elif ideal_values and actual_value not in ideal_values:
                 log_message(results_widget, f"    -> [AVISO] Valor não ideal. Esperado um de: {ideal_values}\n")
        elif header_name not in ["Server", "X-Powered-By"]:
            log_message(results_widget, f"[AVISO] Cabeçalho de segurança '{header_name}' em falta.\n")


def get_forms_from_html(html_content, base_url):
  
    soup = BeautifulSoup(html_content, 'lxml')
    forms_details = []
    for form_tag in soup.find_all('form'):
        action = form_tag.get('action', '')
        method = form_tag.get('method', 'get').lower()
        action_url = urljoin(base_url, action)
        inputs = []
        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            value = input_tag.get('value', '')
            if name:
                inputs.append({'name': name, 'type': input_type, 'value': value})
        if inputs:
            forms_details.append({'action': action_url, 'method': method, 'inputs': inputs})
    return forms_details


def test_vulnerability(target_url, method, data, session, payload_description, payload_value_to_check, check_type, results_widget):
    
    headers = {'User-Agent': USER_AGENT}
    current_action = "Submetendo POST para" if method == 'post' else "Submetendo GET para"
    log_message(results_widget, f"[INFO] {current_action} {target_url} com payload '{payload_description}'\n")
    try:
        if method == 'post':
            response = session.post(target_url, data=data, headers=headers, timeout=7, allow_redirects=True)
        else:
            response = session.get(target_url, params=data, headers=headers, timeout=7, allow_redirects=True)

        if check_type == 'xss':
            if payload_value_to_check in response.text:
                log_message(results_widget, f"    [ALERTA XSS] Payload '{payload_description}' REFLETIDO em {response.url}!\n")
                log_message(results_widget, f"        -> Dados enviados: {data}\n")
                return True
        elif check_type == 'sqli':
            response_text_lower = response.text.lower()
            for error_pattern in SQL_ERROR_PATTERNS:
                if error_pattern in response_text_lower:
                    log_message(results_widget, f"    [ALERTA SQLi] Erro SQL '{error_pattern}' encontrado em {response.url} após injetar '{payload_description}'!\n")
                    log_message(results_widget, f"        -> Dados enviados: {data}\n")
                    return True
    except requests.exceptions.RequestException as e:
        log_message(results_widget, f"    [ERRO] Falha ao submeter para {target_url}: {e}\n")
    return False


def scan_forms_for_vulnerabilities(forms, base_scan_url, session, results_widget):
   
    if not forms:
        log_message(results_widget, "[INFO] Nenhum formulário encontrado nesta página para testar XSS/SQLi.\n")
        return
    log_message(results_widget, f"\n--- Testando Formulários de {base_scan_url} para XSS e SQLi ---\n")
    for form in forms:
        log_message(results_widget, f"[INFO] Analisando formulário com action: {form['action']} (método: {form['method'].upper()})\n")
        for input_field in form['inputs']:
            original_value = input_field.get('value', '')
        
            for xss_payload_val in XSS_PAYLOADS: 
                form_data = {}
                for field in form['inputs']:
                    form_data[field['name']] = xss_payload_val if field['name'] == input_field['name'] else field.get('value', 'test')
                test_vulnerability(form['action'], form['method'], form_data, session,
                                   f"XSS em '{input_field['name']}'", xss_payload_val, 'xss', results_widget)
            # Testar SQLi
            for sqli_payload_name, sqli_payload_val in SQLI_PAYLOADS.items():
                form_data = {}
                for field in form['inputs']:
                    form_data[field['name']] = (original_value + sqli_payload_val) if field['name'] == input_field['name'] else field.get('value', 'test')
                test_vulnerability(form['action'], form['method'], form_data, session,
                                   f"SQLi:{sqli_payload_name} em '{input_field['name']}'", sqli_payload_val, 'sqli', results_widget)


def scan_url_params_for_vulnerabilities(target_url, session, results_widget):
   
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    if not query_params:
       
        return
    log_message(results_widget, f"\n--- Testando Parâmetros de URL de {target_url} para XSS e SQLi ---\n")
    base_url_no_query = parsed_url._replace(query=None).geturl()
    for param_name, param_values in query_params.items():
        original_param_value = param_values[0]
       
        for xss_payload_val in XSS_PAYLOADS:
            temp_params = {k: v if k != param_name else [xss_payload_val] for k, v in query_params.items()}
            test_vulnerability(base_url_no_query, 'get', temp_params, session,
                               f"XSS em param URL '{param_name}'", xss_payload_val, 'xss', results_widget)
       
        for sqli_payload_name, sqli_payload_val in SQLI_PAYLOADS.items():
            temp_params = {k: v if k != param_name else [original_param_value + sqli_payload_val] for k,v in query_params.items()}
            test_vulnerability(base_url_no_query, 'get', temp_params, session,
                               f"SQLi:{sqli_payload_name} em param URL '{param_name}'", sqli_payload_val, 'sqli', results_widget)



def spider_and_collect_links(current_url, base_domain, session, visited_urls_set, urls_to_scan_queue, results_widget):
    """Visita um URL, extrai links internos e adiciona-os à fila se forem novos e dentro do escopo."""
    if current_url in visited_urls_set or len(visited_urls_set) >= MAX_URLS_TO_SCAN : # Evitar revisitar ou exceder limite
        return

    log_message(results_widget, f"[SPIDER] Visitando: {current_url}\n")
    visited_urls_set.add(current_url) 

    headers = {'User-Agent': USER_AGENT}
    try:
        response = session.get(current_url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()

       
        effective_url = response.url
        if urlparse(effective_url).netloc != base_domain:
            log_message(results_widget, f"[SPIDER] Link {effective_url} fora do escopo de {base_domain}.\n")
            return 
        
      

        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            log_message(results_widget, f"[SPIDER] Conteúdo de {effective_url} não é HTML ({content_type}). Ignorando links.\n")
            return response 
        soup = BeautifulSoup(response.text, 'lxml')
        links_found_on_page = 0
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            
            absolute_url = urljoin(effective_url, href)
          
            absolute_url = urlparse(absolute_url)._replace(fragment="").geturl()

           
            if urlparse(absolute_url).netloc == base_domain and \
               absolute_url not in visited_urls_set and \
               absolute_url not in urls_to_scan_queue:
                if len(visited_urls_set) + len(urls_to_scan_queue) < MAX_URLS_TO_SCAN:
                    urls_to_scan_queue.append(absolute_url)
                    log_message(results_widget, f"[SPIDER] Link descoberto e adicionado à fila: {absolute_url}\n")
                    links_found_on_page +=1
                else:
                    log_message(results_widget, f"[SPIDER] Limite de URLs ({MAX_URLS_TO_SCAN}) atingido. Não adicionando mais links.\n")
                    return response
        
        if links_found_on_page == 0:
            log_message(results_widget, f"[SPIDER] Nenhum link novo e dentro do escopo encontrado em {effective_url}.\n")

        return response 

    except requests.exceptions.RequestException as e:
        log_message(results_widget, f"[SPIDER] Erro ao aceder a {current_url} para spidering: {e}\n")
    return None


def run_scan_logic_for_single_url(url_to_scan, session, results_widget, is_initial_url=False):
    """Lógica de scan para um único URL (conectividade, ficheiros, cabeçalhos, formulários, params)."""
    log_message(results_widget, f"\n--- INICIANDO SCAN DETALHADO PARA: {url_to_scan} ---\n")
    
   
    base_response = check_connectivity(url_to_scan, results_widget, session)

    if base_response:
        effective_url = base_response.url 
        html_content = base_response.text

     
        if is_initial_url: 
             scan_common_files(effective_url, results_widget, session)

        analyze_headers(base_response, results_widget)

        content_type = base_response.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type:
            forms = get_forms_from_html(html_content, effective_url)
            scan_forms_for_vulnerabilities(forms, effective_url, session, results_widget)
        else:
            log_message(results_widget, f"[INFO] Conteúdo de {effective_url} não é HTML. Saltando análise de formulários.\n")
        
        scan_url_params_for_vulnerabilities(effective_url, session, results_widget)
        return base_response
    return None


def run_scan_logic(target_url_input, results_widget):
    results_widget.config(state=tk.NORMAL)
    results_widget.delete('1.0', tk.END)
    log_message(results_widget, f"--- Iniciando análise GERAL em: {target_url_input} (Limite de URLs: {MAX_URLS_TO_SCAN}) ---\n")

    parsed_url_input = urlparse(target_url_input)
    if not parsed_url_input.scheme:
        target_url_normalized = 'http://' + target_url_input
        log_message(results_widget, f"[INFO] URL normalizado para: {target_url_normalized}\n")
    else:
        target_url_normalized = target_url_input
    
    parsed_url_norm = urlparse(target_url_normalized)
    if not parsed_url_norm.netloc:
        log_message(results_widget, "[ERRO] URL inválido. Por favor, insira um URL completo (ex: http://exemplo.com).\n")
        results_widget.config(state=tk.DISABLED)
        return

    base_domain = parsed_url_norm.netloc 

    urls_to_scan_queue = collections.deque()
    visited_urls_set = set()

   
    urls_to_scan_queue.append(target_url_normalized)
    
    
    scanned_count = 0

    with requests.Session() as session:
        session.headers.update({'User-Agent': USER_AGENT})

        while urls_to_scan_queue and scanned_count < MAX_URLS_TO_SCAN:
            current_url_to_process = urls_to_scan_queue.popleft()

            if current_url_to_process in visited_urls_set: 
                continue
            
            log_message(results_widget, f"\n[FILA] Processando: {current_url_to_process} ({len(urls_to_scan_queue)} restantes na fila)\n")
            
         
            visited_urls_set.add(current_url_to_process)
            scanned_count += 1
            is_initial = (current_url_to_process == target_url_normalized)

           
            response_from_scan = run_scan_logic_for_single_url(current_url_to_process, session, results_widget, is_initial_url=is_initial)

            
            spider_and_collect_links(current_url_to_process, base_domain, session, visited_urls_set, urls_to_scan_queue, results_widget)
          

        if not urls_to_scan_queue and scanned_count < MAX_URLS_TO_SCAN :
             log_message(results_widget, "\n[INFO] Fila de URLs vazia. Spider concluiu a exploração dentro do escopo e limite.\n")
        elif scanned_count >= MAX_URLS_TO_SCAN:
            log_message(results_widget, f"\n[INFO] Limite de {MAX_URLS_TO_SCAN} URLs atingido. Scan parado.\n")


    log_message(results_widget, "\n--- Análise GERAL concluída ---\n")
    results_widget.config(state=tk.DISABLED)



def start_scan_thread(target_url_entry, results_widget, scan_button):
    url = target_url_entry.get()
    if not url:
        messagebox.showwarning("URL em falta", "Por favor, insira um URL para analisar.")
        return

    scan_button.config(state=tk.DISABLED)
    results_widget.config(state=tk.NORMAL)
    results_widget.delete('1.0', tk.END)

    scan_thread = threading.Thread(target=execute_scan_and_reenable_button,
                                   args=(url, results_widget, scan_button),
                                   daemon=True)
    scan_thread.start()

def execute_scan_and_reenable_button(url, results_widget, scan_button):
    try:
        run_scan_logic(url, results_widget)
    except Exception as e:
        if results_widget.winfo_exists():
            log_message(results_widget, f"[ERRO GERAL NO SCAN] Ocorreu um erro inesperado: {e}\n")
            import traceback
            log_message(results_widget, traceback.format_exc() + "\n")
    finally:
        if scan_button.winfo_exists():
            scan_button.config(state=tk.NORMAL)
        if results_widget.winfo_exists():
            results_widget.config(state=tk.DISABLED)

def setup_gui():
    window = tk.Tk()
    window.title(f"UnderFinder V1(v{USER_AGENT.split('/')[-1]})")
    window.geometry("800x700") 
    style = ttk.Style()
    try:
        available_themes = style.theme_names()
        if 'clam' in available_themes: style.theme_use('clam')
        elif 'vista' in available_themes: style.theme_use('vista')
    except tk.TclError: print("Tema ttk preferido não encontrado.")

    input_frame = ttk.Frame(window, padding="10")
    input_frame.pack(fill=tk.X)

    ttk.Label(input_frame, text="URL Alvo:").pack(side=tk.LEFT, padx=(0, 5))
    target_url_entry = ttk.Entry(input_frame, width=70)
    target_url_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, ipady=2)

    results_widget = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=35, state=tk.DISABLED, relief=tk.SOLID, borderwidth=1) # Aumentado
    results_widget.pack(padx=10, pady=(0, 10), expand=True, fill=tk.BOTH)

    scan_button = ttk.Button(input_frame, text="Analisar com Spider",
                             command=lambda: start_scan_thread(target_url_entry, results_widget, scan_button))
    scan_button.pack(side=tk.LEFT, padx=(5, 0), ipady=2)

    results_widget.config(state=tk.NORMAL)
    log_message(results_widget, f" Welcome Tester (v{USER_AGENT.split('/')[-1]})!\n\n")
    log_message(results_widget, f"URls Tool limit: {MAX_URLS_TO_SCAN}\n")
    log_message(results_widget, "Disclaimer: Use This tool only where you have permission\n")
    log_message(results_widget, "to be on usage.\n")
    log_message(results_widget, "you need 'beautifulsoup4' e 'lxml' instaled: pip install beautifulsoup4 lxml\n\n")
    results_widget.config(state=tk.DISABLED)

    window.mainloop()


if __name__ == "__main__":
    print("*****************************************************************")
    print("*IMPORTANT: SECURITY ANALIST FOR ONLY EDUCACIONAL PURPOSES OR NON ILLEGAL ACTIONS           *")
    
    print(f"* web scanner underfinder{USER_AGENT.split('/')[-1]}                             *")
    print("* Certifique-se de ter as bibliotecas 'beautifulsoup4' e 'lxml' *")
    print("* instaladas: pip install beautifulsoup4 lxml                   *")
    print("*****************************************************************\n")
    setup_gui()
