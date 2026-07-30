# utils.py
import pandas as pd
import numpy as np
import re
import joblib
import torch
import json
import os
import glob # Para encontrar archivos .eml
import email # Módulo estándar para parsear emails
from email import policy
from email.parser import BytesParser # Para leer como bytes
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler, LabelEncoder
from category_encoders import HashingEncoder
from transformers import XLMRobertaTokenizer, XLMRobertaModel
from torch.cuda.amp import autocast
from tqdm import tqdm # Usar tqdm estándar para scripts y notebooks
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn.metrics import precision_recall_curve, f1_score, classification_report
from time import time
# Intentar importar BeautifulSoup, si falla, imprimir advertencia
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("⚠️ BeautifulSoup4 no encontrado (`pip install beautifulsoup4`). La limpieza de HTML en EMLs será básica.")

# Importar constantes de config (Asegúrate de que config.py esté en el mismo directorio o en el PYTHONPATH)
try:
    import config
    # Importar optuna específicamente si está disponible (para conversión de grid)
    if config.OPTUNA_AVAILABLE:
        import optuna
        from optuna.integration import OptunaSearchCV
except ImportError as e:
    print(f"❌ ERROR: No se pudo importar '{e.name}'. Asegúrate de que existe y es accesible.")
    raise

# --- Funciones de Carga y Limpieza Inicial (CSV) ---
def load_and_combine_data(file_paths, expected_cols, target_col, missing_val_str=config.MISSING_VALUE_STR):
    """Carga, unifica y limpia inicial datasets CSV."""
    all_data = []
    print(f"--- Iniciando carga y unificación de {len(file_paths)} datasets CSV ---")

    for file in tqdm(file_paths, desc="Cargando Archivos CSV"):
        try:
            try:
                # Intentar leer con encoding por defecto (usualmente utf-8)
                df = pd.read_csv(file)
            except UnicodeDecodeError:
                print(f"  ... Reintentando con 'latin1' para {os.path.basename(file)}")
                df = pd.read_csv(file, encoding='latin1')
            # Manejar potenciales errores de parseo si columnas son inconsistentes
            except pd.errors.ParserError as pe:
                 print(f"  ... Error de parseo en {os.path.basename(file)}. Intentando con `on_bad_lines='skip'`: {pe}")
                 try:
                    df = pd.read_csv(file, encoding='latin1', on_bad_lines='skip') # O engine='python'
                 except Exception as e_skip:
                     print(f"  ... Falló el reintento con skip. Omitiendo archivo {os.path.basename(file)}: {e_skip}")
                     continue # Saltar este archivo
            all_data.append(df)
        except FileNotFoundError:
             print(f"❌ ERROR: Archivo no encontrado {file}. Se omitirá.")
        except Exception as e:
            print(f"❌ ERROR inesperado al cargar {file}: {e}")

    if not all_data:
        print("❌ No se pudo cargar ningún dataset CSV. Retornando DataFrame vacío.")
        return pd.DataFrame()

    df_combined = pd.concat(all_data, ignore_index=True)
    print(f"✅ Tamaño inicial combinado (CSV): {df_combined.shape}")

    # Estandarizar nombres (minúsculas y reemplazo simple)
    df_combined.columns = df_combined.columns.str.lower().str.replace('sender', 'from').str.replace('receiver', 'to').str.replace('label', 'phish')
    # Mapeo específico si aún se usan nombres antiguos después de lowercasing
    column_mapping = {'subject': 'Subject', 'body': 'Body', 'date':'Date', 'from':'From', 'to':'To', 'phish':config.TARGET_COLUMN, 'urls':'Original_URLs'}
    df_combined.rename(columns=lambda c: column_mapping.get(c, c), inplace=True) # Renombrar a formato CamelCase esperado


    # Asegurar columnas esperadas y rellenar nulos
    for col in expected_cols: # Usa expected_csv_cols que incluye 'urls' ('Original_URLs' ahora)
         if col not in df_combined.columns:
            # Manejar caso especial de 'urls' vs 'Original_URLs'
            if col == 'urls' and 'Original_URLs' in df_combined.columns:
                 continue # Ya está renombrada
            print(f"⚠️ Columna CSV requerida '{col}' no encontrada. Se creará con valor por defecto.")
            df_combined[col] = 0 if col == target_col else missing_val_str

         # Rellenar nulos existentes
         if df_combined[col].dtype == object or col not in [target_col]:
              df_combined[col] = df_combined[col].fillna(missing_val_str).astype(str)
         elif col == target_col:
              # Limpiar target de no numéricos ANTES de rellenar NaN
              df_combined[col] = pd.to_numeric(df_combined[col], errors='coerce')
              df_combined[col] = df_combined[col].fillna(0).astype(int) # Rellenar NaN numéricos con 0

    # Procesamiento específico de URLs de la columna 'Original_URLs' (antes 'urls')
    if 'Original_URLs' in df_combined.columns:
         print("--- Procesando columna 'Original_URLs' (CSV) para crear 'Concatenated_URLs' ---")
         df_combined['Concatenated_URLs'] = df_combined['Original_URLs'].apply(create_concatenated_urls)
         df_combined.drop(columns=['Original_URLs'], inplace=True, errors='ignore') # Eliminar columna original
    elif 'Concatenated_URLs' not in df_combined.columns: # Si 'urls' no existía
        print("⚠️ Columna 'Original_URLs' ('urls') no encontrada. 'Concatenated_URLs' tendrá valor por defecto.")
        df_combined['Concatenated_URLs'] = missing_val_str

    # Orden final y limpieza de target NaN remanentes
    final_cols_order = config.EXPECTED_PARSED_COLS # Usar las columnas finales esperadas
    existing_cols = [col for col in final_cols_order if col in df_combined.columns]
    # Asegurarse de que la columna target exista antes de intentar usarla
    if target_col not in df_combined.columns:
        print(f"❌ ERROR: La columna target '{target_col}' no existe en el DataFrame después de la carga CSV.")
        return pd.DataFrame()

    df_combined = df_combined[existing_cols] # Reordenar con columnas existentes

    rows_before = len(df_combined)
    # Volver a verificar NaNs en target por si acaso
    df_combined.dropna(subset=[target_col], inplace=True)
    rows_after = len(df_combined)
    if rows_before != rows_after:
        print(f"⚠️ Se eliminaron {rows_before - rows_after} filas CSV con target inválido tras limpieza final.")

    print(f"✅ Tamaño final unificado y limpio (CSV): {df_combined.shape}")
    print("--- ✅ Carga, Unificación y Limpieza CSV Finalizada ---")
    return df_combined

def create_concatenated_urls(url_value):
    """Limpia y concatena URLs de la columna 'urls' de los CSV o devuelve 'No Data'."""
    missing_val_str = config.MISSING_VALUE_STR
    # Comprobar NaN y representaciones comunes de ausencia/cero
    if pd.isna(url_value) or str(url_value).strip().lower() in ['0', '0.0', '', 'nan', 'none']:
        return missing_val_str
    else:
        url_str = str(url_value).strip()
        # Limpiar caracteres de formato de lista/tupla y saltos de línea escapados
        url_str = re.sub(r'\\n|\\r', ' ', url_str)
        url_str = re.sub(r'[\[\]\'"]', '', url_str)
        url_str = re.sub(r'\s+', ' ', url_str).strip() # Limpiar espacios múltiples

        # Caso específico TREC donde '1' indica presencia pero no URL
        if url_str == '1':
             return missing_val_str

        # Intentar separar URLs pegadas (heurística simple)
        url_str = re.sub(r'(https?://)', r' \1', url_str).strip()
        result = ' '.join(url_str.split()) # Unificar espacios de nuevo

        # Devolver resultado o valor por defecto si queda vacío
        return result if result else missing_val_str

# --- Funciones para Procesar EML ---

def decode_payload(part):
    """Decodifica el payload de una parte del email, manejando encodings."""
    payload = part.get_payload(decode=True) # decode=True maneja Base64, Quoted-Printable
    charset = part.get_content_charset()
    fallback_encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252', 'ascii']

    if payload:
        decoded_payload = None
        if charset:
            try:
                decoded_payload = payload.decode(charset, errors='replace')
            except (LookupError, UnicodeDecodeError):
                pass # Intentar fallbacks

        if decoded_payload is None: # Si charset falló o no existía
            for encoding in fallback_encodings:
                try:
                    decoded_payload = payload.decode(encoding, errors='replace')
                    # print(f"Debug: Decodificado con {encoding}") # Para depuración
                    break # Éxito
                except UnicodeDecodeError:
                    continue # Probar siguiente

        # Si aún falla, devolver representación de bytes reemplazando errores
        return decoded_payload if decoded_payload is not None else payload.decode('ascii', errors='replace')

    return "" # Devolver cadena vacía si no hay payload

def extract_body_from_eml(msg):
    """Extrae el cuerpo del texto (preferiblemente plano, luego HTML limpio) de un objeto Message."""
    body_plain = None
    body_html = None

    if msg.is_multipart():
        # Usar walk para recorrer todas las partes, incluyendo anidadas
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))

            # Saltar adjuntos explícitos o partes sin contenido textual probable
            if 'attachment' in content_disposition or not content_type.startswith('text/'):
                continue

            # Priorizar el primer texto plano encontrado
            if content_type == 'text/plain' and body_plain is None:
                body_plain = decode_payload(part)
            # Guardar el primer HTML encontrado como fallback
            elif content_type == 'text/html' and body_html is None:
                body_html = decode_payload(part)

            # Si ya tenemos ambos, podemos parar (o seguir si queremos lógica más compleja)
            # if body_plain is not None and body_html is not None:
            #    break
    else:
        # Email no multipart
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            body_plain = decode_payload(msg)
        elif content_type == 'text/html':
            body_html = decode_payload(msg)

    # Procesar y devolver el cuerpo encontrado
    if body_plain:
        # Limpiar espacios extra y saltos de línea del texto plano
        cleaned_plain = re.sub(r'\s+', ' ', body_plain).strip()
        return cleaned_plain if cleaned_plain else config.MISSING_VALUE_STR

    elif body_html:
        # Limpiar HTML si BeautifulSoup está disponible
        if BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(body_html, 'html.parser')
                # Extraer texto, separando con espacio, quitar espacios redundantes
                text = soup.get_text(separator=' ', strip=True)
                cleaned_html = re.sub(r'\s+', ' ', text).strip()
                return cleaned_html if cleaned_html else config.MISSING_VALUE_STR
            except Exception as e:
                # print(f"Debug: Error cleaning HTML with BS4 - {e}")
                # Fallback: devolver HTML decodificado pero sin limpiar tags
                cleaned_html_basic = re.sub(r'\s+', ' ', body_html).strip()
                return cleaned_html_basic if cleaned_html_basic else config.MISSING_VALUE_STR
        else:
            # Si BS4 no está, devolver HTML decodificado (limpieza mínima de espacios)
            cleaned_html_basic = re.sub(r'\s+', ' ', body_html).strip()
            return cleaned_html_basic if cleaned_html_basic else config.MISSING_VALUE_STR
    else:
        # Si no se encontró cuerpo textual
        return config.MISSING_VALUE_STR

def parse_eml_file(file_path):
    """Parsea un archivo .eml y extrae los campos relevantes."""
    try:
        with open(file_path, 'rb') as f: # Leer como bytes
            # Usar policy.default para manejo robusto de headers y encodings
            msg = BytesParser(policy=policy.default).parse(f)

        # Extraer headers usando .get() y decodificación automática de policy.default
        from_header = str(msg.get('From', config.MISSING_VALUE_STR))
        to_header = str(msg.get('To', config.MISSING_VALUE_STR))
        subject_header = str(msg.get('Subject', config.MISSING_VALUE_STR))
        date_header = str(msg.get('Date', config.MISSING_VALUE_STR))

        # Limpiar saltos de línea dentro de los headers (a veces ocurren)
        from_header = re.sub(r'\s+', ' ', from_header).strip()
        to_header = re.sub(r'\s+', ' ', to_header).strip()
        subject_header = re.sub(r'\s+', ' ', subject_header).strip()
        date_header = re.sub(r'\s+', ' ', date_header).strip()


        data = {
            'From': from_header if from_header else config.MISSING_VALUE_STR,
            'To': to_header if to_header else config.MISSING_VALUE_STR,
            'Subject': subject_header if subject_header else config.MISSING_VALUE_STR,
            'Date': date_header if date_header else config.MISSING_VALUE_STR,
            'Body': extract_body_from_eml(msg) # Extraer y limpiar cuerpo
            # 'Concatenated_URLs' se generará después a partir del Body
        }
        return data
    except Exception as e:
        print(f"❌ ERROR al parsear {os.path.basename(file_path)}: {e}")
        # Devolver dict con valores por defecto en caso de fallo para no perder la fila
        return {
            'From': config.MISSING_VALUE_STR, 'To': config.MISSING_VALUE_STR,
            'Subject': config.MISSING_VALUE_STR, 'Date': config.MISSING_VALUE_STR,
            'Body': config.MISSING_VALUE_STR, config.TARGET_COLUMN: 1 # Asumir phishing si falla? O omitir? Omitir es más seguro.
        }
        # return None # O devolver None y filtrar después

def process_eml_directory(dir_path, target_value=1):
    """Procesa todos los .eml en un directorio y devuelve un DataFrame limpio."""
    # Buscar recursivamente archivos .eml
    eml_files = glob.glob(os.path.join(dir_path, '**', '*.eml'), recursive=True)
    if not eml_files:
        print(f"⚠️ No se encontraron archivos .eml en: {dir_path} (recursivo)")
        return pd.DataFrame(columns=config.EXPECTED_PARSED_COLS) # Devolver DF vacío con columnas esperadas

    all_email_data = []
    print(f"--- Procesando {len(eml_files)} archivos .eml de {dir_path} ---")
    for file_path in tqdm(eml_files, desc="Parseando EMLs"):
        parsed_data = parse_eml_file(file_path)
        # Solo añadir si el parseo fue exitoso y devolvió un diccionario válido
        if parsed_data and isinstance(parsed_data, dict) and config.TARGET_COLUMN not in parsed_data: # Evitar añadir los dict de error si decidimos no ponerles target
             parsed_data[config.TARGET_COLUMN] = target_value # Asignar etiqueta Phishing
             all_email_data.append(parsed_data)
        elif parsed_data and config.TARGET_COLUMN in parsed_data: # Si el dict de error tiene target (no recomendado)
             all_email_data.append(parsed_data)


    if not all_email_data:
        print("❌ No se pudo parsear exitosamente ningún archivo .eml.")
        return pd.DataFrame(columns=config.EXPECTED_PARSED_COLS)

    df = pd.DataFrame(all_email_data)
    print(f"✅ DataFrame creado desde EMLs. Tamaño inicial: {df.shape}")

    # Extraer URLs del Body para crear Concatenated_URLs
    print("--- Extrayendo URLs del cuerpo de los EMLs ---")
    # Asegurarse de que Body es string antes de aplicar regex
    df['Concatenated_URLs'] = df['Body'].astype(str).apply(extract_urls_from_body_text)

    # Rellenar NaNs residuales y asegurar tipos/columnas finales
    for col in config.EXPECTED_PARSED_COLS:
        if col not in df.columns:
             print(f"⚠️ Columna final '{col}' no generada desde EMLs. Creando con valor por defecto.")
             df[col] = 0 if col == config.TARGET_COLUMN else config.MISSING_VALUE_STR
        else:
             # Rellenar NaNs que puedan quedar y asegurar tipo string para texto/categorías
             if df[col].dtype == object or col not in [config.TARGET_COLUMN, 'Date']: # No forzar Date a string aquí
                  df[col] = df[col].fillna(config.MISSING_VALUE_STR).astype(str)
             elif col == config.TARGET_COLUMN:
                  # Asegurar que target sea numérico entero
                  df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
             # Nota: La columna 'Date' se mantiene como string aquí, se parseará en extract_time_feature

    # Ordenar y seleccionar columnas finales
    df = df[config.EXPECTED_PARSED_COLS]

    # Limpieza final de target por si acaso
    rows_before = len(df)
    df.dropna(subset=[config.TARGET_COLUMN], inplace=True)
    rows_after = len(df)
    if rows_before != rows_after:
        print(f"⚠️ Se eliminaron {rows_before - rows_after} filas EML con target inválido tras limpieza final.")

    print(f"✅ DataFrame final desde EMLs. Tamaño: {df.shape}")
    return df

# --- Función para extraer URLs del CUERPO de texto ---
def extract_urls_from_body_text(body_text):
    """Extrae y concatena URLs válidas del texto del cuerpo."""
    if not isinstance(body_text, str) or not body_text:
        return config.MISSING_VALUE_STR
    # Regex mejorada para capturar URLs (http, https, ftp, www)
    url_pattern = re.compile(
        r'(?:(?:https?|ftp):\/\/|www\.)'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # dominio
        r'localhost|' # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # IP
        r'(?::\d+)?' # puerto
        r'(?:[/?]\S*)?', re.IGNORECASE) # path (no captura si es solo '/')

    urls = url_pattern.findall(body_text)

    valid_urls = []
    for url in urls:
        # Pre-limpieza: añadir http:// si falta y empieza con www
        if url.lower().startswith('www.'):
            url = 'http://' + url

        try:
             parsed = urlparse(url)
             # Requiere esquema y un netloc (dominio/IP) que contenga al menos un punto o sea localhost/IP
             is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc)
             if parsed.scheme in ['http', 'https', 'ftp'] and ('.' in parsed.netloc or parsed.netloc == 'localhost' or is_ip):
                 # Limpiar puntuación común al final
                 cleaned_url = re.sub(r'[.,)\]}>\'"?]+$', '', url.strip())
                 valid_urls.append(cleaned_url)
        except ValueError:
             continue # Ignorar si urlparse falla

    result = ' '.join(valid_urls)
    return result if result else config.MISSING_VALUE_STR


def extract_time_feature(df):
    """Extrae la hora (0-23) del campo 'Date' y devuelve el DF."""
    df_copy = df.copy()
    if 'Date' in df_copy.columns:
        # --- MODIFICACIÓN --
        print("   ... (extract_time_feature) Parseando 'Date' con pd.to_datetime...")
        df_copy['Date_dt'] = pd.to_datetime(df_copy['Date'], errors='coerce', utc=True) 
        # --- FIN MODIFICACIÓN ---
        
        df_copy[config.TIME_FEATURE] = df_copy['Date_dt'].dt.hour.astype(float).fillna(0)
        df_copy.drop(columns=['Date_dt'], inplace=True, errors='ignore') 
        print("   ... (extract_time_feature) 'Date' parseada. 'Hour_temp' creada.")
    else:
        print("⚠️ Columna 'Date' no encontrada. Creando feature de hora con ceros.")
        df_copy[config.TIME_FEATURE] = 0.0
    return df_copy

def fit_preprocess_additional_features(df_train):
    """Ajusta HashingEncoder y StandardScaler en datos de entrenamiento."""
    if config.TARGET_COLUMN not in df_train.columns:
        raise ValueError(f"La columna target '{config.TARGET_COLUMN}' no se encontró en df_train.")

    # --- INICIO: LOGS DE DIAGNÓSTICO ---
    print("--- (fit_preprocess) 1. Llamando a extract_time_feature ---")
    df_processed = extract_time_feature(df_train)
    print("--- (fit_preprocess) 2. extract_time_feature completado ---")
    
    label_encoders = {} 
    fitted_data_list = []
    feature_names_for_scaler = [] 

    N_HASH_COMPONENTS = 100 
    cols_to_hash = [col for col in config.CATEGORICAL_FEATURES if col in df_processed.columns]
    
    if not cols_to_hash:
        print(f"⚠️ No se encontraron columnas categóricas {config.CATEGORICAL_FEATURES}.")
        hasher = HashingEncoder(cols=[], n_components=N_HASH_COMPONENTS, return_df=True)
        fitted_data_hashed = pd.DataFrame(index=df_processed.index)
    else:
        print(f"--- (fit_preprocess) 3. Aplicando HashingEncoder a {cols_to_hash} ---")
        hasher = HashingEncoder(
            cols=cols_to_hash, 
            n_components=N_HASH_COMPONENTS,
            return_df=True 
        )
        
        print("--- (fit_preprocess) 4. Preparando datos para hasher (.astype(str).fillna) ---")
        # Esta línea puede ser la que consume mucha RAM
        df_processed_cat = df_processed[cols_to_hash].astype(str).fillna(config.MISSING_VALUE_STR)
        
        print("--- (fit_preprocess) 5. Llamando a hasher.fit_transform ---")
        fitted_data_hashed = hasher.fit_transform(df_processed_cat)
        print("--- (fit_preprocess) 6. hasher.fit_transform completado ---")

    label_encoders['feature_hasher'] = hasher
    
    if not fitted_data_hashed.empty:
        fitted_data_list.append(fitted_data_hashed.values)
        feature_names_for_scaler.extend(list(fitted_data_hashed.columns))

    if config.TIME_FEATURE in df_processed.columns:
        time_values = df_processed[[config.TIME_FEATURE]].fillna(0).values
        fitted_data_list.append(time_values)
        feature_names_for_scaler.append(config.TIME_FEATURE)
    else:
         print(f"⚠️ Columna de tiempo '{config.TIME_FEATURE}' no generada.")

    print("--- (fit_preprocess) 7. Ajustando Target Encoder ---")
    target_encoder = LabelEncoder()
    target_encoder.fit(df_train[config.TARGET_COLUMN].values)
    label_encoders['target_encoder'] = target_encoder
    print("✅ Target Encoder (Phish) ajustado.")

    if not fitted_data_list:
        print("❌ No hay features categóricas ni de tiempo para escalar.")
        scaler = StandardScaler()
        scaler.feature_names_in_ = np.array([], dtype=object)
        return np.array([]).reshape(len(df_train), 0), label_encoders, scaler

    print("--- (fit_preprocess) 8. Combinando (hstack) features para scaler ---")
    features_to_scale = np.hstack(fitted_data_list).astype(float) 

    print("--- (fit_preprocess) 9. Ajustando StandardScaler ---")
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(features_to_scale)
    scaler.feature_names_in_ = np.array(feature_names_for_scaler, dtype=object)
    print(f"✅ Scaler ajustado con features: {scaler.feature_names_in_}")
    print("--- (fit_preprocess) 10. fit_preprocess completado ---")
    # --- FIN: LOGS DE DIAGNÓSTICO ---

    return scaled_data, label_encoders, scaler


def transform_preprocess_additional_features(df, label_encoders, scaler):
    """
    Aplica preprocesadores (Hashing, Time, Scaling) ya ajustados a nuevos datos.
    """
    # Importar numpy y pandas (necesarios para .values, .fillna, etc.)
    # Ya están importados al inicio de utils.py, pero por claridad:
    import numpy as np
    import pandas as pd
    
    print("--- (transform_preprocess) 1. Llamando a extract_time_feature ---")
    # Llama a la función del mismo módulo (utils)
    # Asumimos que extract_time_feature existe en utils.py (lo cual es cierto)
    df_processed = extract_time_feature(df) 
    
    # 2. Cargar HashingEncoder ajustado
    hasher = label_encoders['feature_hasher']
    
    # 3. Aplicar HashingEncoder
    cols_to_hash = [col for col in config.CATEGORICAL_FEATURES if col in df_processed.columns]
    
    # Comprobar cuántas columnas hash espera el scaler (basado en el ajuste)
    num_hash_cols_expected = len([f for f in scaler.feature_names_in_ if f.startswith('col_')])
    
    if not cols_to_hash:
        print(f"   ... (transform_preprocess) ⚠️ No se encontraron columnas categóricas. Creando {num_hash_cols_expected} columnas de ceros.")
        transformed_data_hashed_values = np.zeros((len(df_processed), num_hash_cols_expected))
    else:
        print(f"   ... (transform_preprocess) 2. Aplicando HashingEncoder (transform) a {cols_to_hash} ---")
        df_processed_cat = df_processed[cols_to_hash].astype(str).fillna(config.MISSING_VALUE_STR)
        transformed_data_hashed = hasher.transform(df_processed_cat)
        transformed_data_hashed_values = transformed_data_hashed.values
        
        # Validar número de columnas hash generadas
        if transformed_data_hashed_values.shape[1] != num_hash_cols_expected:
            print(f"   ... (transform_preprocess) ❌ ERROR: Hasher generó {transformed_data_hashed_values.shape[1]} cols, Scaler espera {num_hash_cols_expected}.")
            # Ajustar a la expectativa del scaler (ej. rellenar con ceros si faltan)
            if transformed_data_hashed_values.shape[1] < num_hash_cols_expected:
                 pad_width = num_hash_cols_expected - transformed_data_hashed_values.shape[1]
                 transformed_data_hashed_values = np.pad(transformed_data_hashed_values, ((0,0), (0, pad_width)), 'constant', constant_values=0)
                 print(f"   ... (transform_preprocess) ✅ Ajustado (padding) a {num_hash_cols_expected} cols.")
            else: # Truncar si hay de más
                 transformed_data_hashed_values = transformed_data_hashed_values[:, :num_hash_cols_expected]
                 print(f"   ... (transform_preprocess) ✅ Ajustado (truncado) a {num_hash_cols_expected} cols.")


    # 4. Obtener feature de tiempo
    time_values = None
    # Solo procesar la columna de tiempo si el scaler la espera
    if config.TIME_FEATURE in scaler.feature_names_in_:
        if config.TIME_FEATURE in df_processed.columns:
            print(f"   ... (transform_preprocess) 3. Obteniendo feature '{config.TIME_FEATURE}' ---")
            time_values = df_processed[[config.TIME_FEATURE]].fillna(0).values
        else:
            print(f"   ... (transform_preprocess) ⚠️ Columna '{config.TIME_FEATURE}' no encontrada. Usando ceros.")
            time_values = np.zeros((len(df_processed), 1))
    
    # 5. Combinar (hstack) en el mismo orden que en 'fit'
    print("   ... (transform_preprocess) 4. Combinando (hstack) features para scaler ---")
    features_to_scale_list = []
    
    # Orden: hash primero, luego tiempo (basado en 'fit_preprocess_additional_features')
    features_to_scale_list.append(transformed_data_hashed_values)
    
    if time_values is not None:
         features_to_scale_list.append(time_values)
    
    if not features_to_scale_list:
         print("   ... (transform_preprocess) ❌ No hay features para escalar.")
         return np.array([]).reshape(len(df_processed), 0)

    features_to_scale = np.hstack(features_to_scale_list).astype(float)
    
    # 6. Aplicar StandardScaler
    print("   ... (transform_preprocess) 5. Aplicando StandardScaler (transform) ---")
    
    # Validar dimensiones finales
    if features_to_scale.shape[1] != len(scaler.feature_names_in_):
         print(f"   ... (transform_preprocess) ❌ ERROR DE DIMENSIÓN FINAL: Datos tienen {features_to_scale.shape[1]} features, Scaler espera {len(scaler.feature_names_in_)}.")
         print(f"   ... Scaler espera: {scaler.feature_names_in_}")
         raise ValueError(f"Inconsistencia de features: se generaron {features_to_scale.shape[1]} features, pero el scaler fue ajustado con {len(scaler.feature_names_in_)}")

    scaled_data = scaler.transform(features_to_scale)
    print("   ... (transform_preprocess) 6. transform_preprocess completado ---")
    return scaled_data

# --- FIN DEL CÓDIGO A PEGAR ---


def set_dynamic_model_weights(y_train, models_tune, models_no_tune):
    """
    Calcula y establece ponderaciones de clase dinámicas (ej. scale_pos_weight) 
    para modelos específicos (como XGBoost) basados en los datos de entrenamiento.
    Modifica los diccionarios de modelos 'in-place'.
    """
    print("\n--- ⚖️  Calculando Ponderaciones de Clase Dinámicas ---")
    
    # 1. Calcular scale_pos_weight para XGBoost
    try:
        # Asume 0=Clase Negativa (mayoritaria), 1=Clase Positiva (minoritaria)
        counts = np.bincount(y_train) 
        if len(counts) > 1 and counts[1] > 0:
            xgb_scale_weight = counts[0] / counts[1]
            print(f"  Calculo de 'scale_pos_weight' para XGBoost: {xgb_scale_weight:.4f} (Neg/Pos)")
        else:
            print("  ⚠️ No se pudo calcular 'scale_pos_weight' (clase 1 = 0 muestras?). Se usará 1.0.")
            xgb_scale_weight = 1.0
    except Exception as e_scale:
        print(f"  ❌ Error calculando 'scale_pos_weight': {e_scale}. Se usará 1.0.")
        xgb_scale_weight = 1.0

    if 'XGBoost' in models_tune:
        try:
            models_tune['XGBoost'].set_params(scale_pos_weight=xgb_scale_weight)
            print(f"  ✅ 'scale_pos_weight' establecido en XGBoost (Tune).")
        except Exception as e_set:
            print(f"  ❌ Error estableciendo 'scale_pos_weight' en XGBoost (Tune): {e_set}")

    if 'XGBoost' in models_no_tune:
         try:
            models_no_tune['XGBoost'].set_params(scale_pos_weight=xgb_scale_weight)
            print(f"  ✅ 'scale_pos_weight' establecido en XGBoost (No-Tune).")
         except Exception as e_set:
             print(f"  ❌ Error estableciendo 'scale_pos_weight' en XGBoost (No-Tune): {e_set}")
    
    
    print("--- ✅ Ponderaciones Dinámicas Establecidas ---")


# --- Funciones de Feature Engineering (BERT) ---
def get_bert_model_and_tokenizer():
    """Carga y devuelve el modelo y tokenizador BERT."""
    print("--- Cargando modelo y tokenizador BERT ---")
    try:
        tokenizer = XLMRobertaTokenizer.from_pretrained(config.BERT_MODEL_NAME)
        model = XLMRobertaModel.from_pretrained(config.BERT_MODEL_NAME)
        model.to(config.DEVICE)
        model.eval() # Poner en modo evaluación
        print(f"✅ Modelo BERT '{config.BERT_MODEL_NAME}' cargado en {config.DEVICE}.")
        return tokenizer, model
    except Exception as e:
        print(f"❌ ERROR al cargar el modelo BERT: {e}")
        raise

def generate_bert_embeddings(texts, tokenizer, model):
    """Genera embeddings BERT [CLS] para una lista de textos usando GPU y autocast."""
    if not texts:
        print("⚠️ Lista de textos vacía para generar embeddings BERT.")
        embedding_dim = model.config.hidden_size if hasattr(model, 'config') else 768
        return np.empty((0, embedding_dim), dtype=np.float32)

    embeddings = []
    autocast_device_type = 'cuda' if config.DEVICE.type == 'cuda' else 'cpu'
    if autocast_device_type == 'cuda':
        dtype = torch.float16
    elif hasattr(torch, 'bfloat16'):
         dtype = torch.bfloat16
    else:
         dtype = torch.float32 

    embedding_dim = model.config.hidden_size if hasattr(model, 'config') else 768

    print(f"--- Generando Embeddings BERT (Device: {config.DEVICE}, DType: {dtype}, Batch: {config.BATCH_SIZE}, Len: {config.MAX_LENGTH}) ---")

    # `enabled` controla si se usa autocast (solo en CUDA)
    with autocast(enabled=(config.DEVICE.type == 'cuda'), dtype=dtype):
        for i in tqdm(range(0, len(texts), config.BATCH_SIZE), desc="Generando Embeddings BERT"):
            batch_texts = texts[i:i + config.BATCH_SIZE]
            # Usar array pre-inicializado con ceros como fallback
            batch_embeddings_np = np.zeros((len(batch_texts), embedding_dim), dtype=np.float32)

            try:
                encoded_batch = tokenizer.batch_encode_plus(
                    batch_texts,
                    max_length=config.MAX_LENGTH,
                    padding='max_length', # Pad to max_length
                    truncation=True,    # Truncate to max_length
                    return_tensors='pt', # Return PyTorch tensors
                    add_special_tokens=True # Add [CLS] and [SEP]
                )
                # Mover tensores al dispositivo correcto
                encoded_batch = {k: v.to(config.DEVICE) for k, v in encoded_batch.items()}

                # Ejecutar inferencia sin cálculo de gradientes
                with torch.no_grad():
                    outputs = model(**encoded_batch)

                # Extraer el embedding del token [CLS] (índice 0)
                last_hidden_states = outputs.last_hidden_state
                # Mover a CPU, convertir a numpy, y asegurar float32
                batch_embeddings_np = last_hidden_states[:, 0, :].cpu().numpy().astype(np.float32)

            except Exception as e:
                 print(f"⚠️ ERROR en tokenización o inferencia BERT en batch {i//config.BATCH_SIZE}: {e}. Usando embeddings de ceros.")
                 # batch_embeddings_np ya está inicializado con ceros

            embeddings.append(batch_embeddings_np)


    if not embeddings:
         print("⚠️ No se generaron embeddings BERT.")
         return np.empty((0, embedding_dim), dtype=np.float32)

    print("✅ Embeddings BERT generados.")
    return np.vstack(embeddings)


# --- Funciones de Modelado y Evaluación ---
def tune_model_with_cv(model, grid, X_train, y_train, name):
    """Realiza búsqueda de hiperparámetros con CV (Optuna o GridSearchCV)."""
    print(f"\n[{name}] Iniciando Búsqueda de Hiperparámetros ({config.CV_SPLITS}-Fold CV)...")
    start_time = time()
    # Usar StratifiedKFold para mantener proporción de clases en folds
    skf = StratifiedKFold(n_splits=config.CV_SPLITS, shuffle=True, random_state=config.RANDOM_STATE)

    search_cv = None
    best_estimator = model # Default al modelo base si CV falla

    try:
        if config.OPTUNA_AVAILABLE and 'optuna' in globals():
            print(f"[{name}] Usando OptunaSearchCV.")
            if not grid: # Si no hay grid definido para este modelo
                print(f"⚠️ No hay grid de búsqueda Optuna para {name}. Entrenando modelo base.")
                search_cv = model.fit(X_train, y_train) # Ajustar modelo base
                best_estimator = search_cv
                best_score = f1_score(y_train, best_estimator.predict(X_train)) # Score en train como placeholder
                best_params = {}
            else:
                search_cv = OptunaSearchCV(
                    estimator=model, param_distributions=grid, n_trials=10, # Puedes aumentar n_trials
                    scoring='f1', cv=skf, verbose=0, n_jobs=-1, random_state=config.RANDOM_STATE,
                    error_score=0.0 # Asignar 0 si un trial falla, en lugar de detenerse
                )
                search_cv.fit(X_train, y_train)
                best_estimator = search_cv.best_estimator_
                best_score = search_cv.best_score_
                best_params = search_cv.best_params_

        else: # Fallback a GridSearchCV
            print(f"[{name}] Usando GridSearchCV como fallback.")
            grid_cv = {}
            if not grid: # Si no hay grid definido
                 print(f"⚠️ No hay grid de búsqueda GridSearchCV para {name}. Entrenando modelo base.")
                 search_cv = model.fit(X_train, y_train)
                 best_estimator = search_cv
                 best_score = f1_score(y_train, best_estimator.predict(X_train)) # Score en train
                 best_params = {}
            else:
                 # Convertir grid de Optuna (si existe) a formato GridSearchCV
                 for k, v in grid.items():
                      if config.OPTUNA_AVAILABLE and hasattr(v, 'sample'): # Es distribución Optuna
                          if isinstance(v, optuna.distributions.CategoricalDistribution):
                              grid_cv[k] = v.choices
                          elif isinstance(v, (optuna.distributions.IntDistribution, optuna.distributions.FloatDistribution)):
                              low = getattr(v, 'low', 0); high = getattr(v, 'high', 1)
                              dtype = int if isinstance(v, optuna.distributions.IntDistribution) else float
                              # Crear 3 puntos para la rejilla simple
                              grid_cv[k] = list(np.unique(np.linspace(low, high, 3, dtype=dtype)))
                      else: # Ya es lista/valor compatible
                          grid_cv[k] = v

                 search_cv = GridSearchCV(
                     estimator=model, param_grid=grid_cv, scoring='f1',
                     cv=skf, verbose=0, n_jobs=-1,
                     error_score=0.0 # Asignar 0 si un trial falla
                 )
                 search_cv.fit(X_train, y_train)
                 best_estimator = search_cv.best_estimator_
                 best_score = search_cv.best_score_
                 best_params = search_cv.best_params_

    except Exception as e:
        print(f"❌ ERROR durante la búsqueda de hiperparámetros para {name}: {e}")
        try:
             # Intentar ajustar el modelo base como fallback si el CV falló completamente
             if not hasattr(best_estimator, 'classes_') or not getattr(best_estimator, '_is_fitted', False):
                 print(f"   Ajustando modelo base {name} como fallback...")
                 best_estimator.fit(X_train, y_train)
             best_score = -1 # Indicar fallo de CV
             best_params = {"cv_error": str(e)}
        except Exception as fit_e:
             print(f"❌ ERROR FATAL al ajustar el modelo base {name} tras fallo de CV: {fit_e}")
             # Si ni siquiera el modelo base se puede ajustar, devolver None
             return None, -1, time() - start_time # Indicar fallo total

    train_time = time() - start_time
    # Usar getattr por si best_score_ o best_params_ no existen (caso de fallo o modelo base)
    final_best_score = getattr(search_cv, 'best_score_', best_score if 'best_score' in locals() else -1)
    final_best_params = getattr(search_cv, 'best_params_', best_params if 'best_params' in locals() else {})

    print(f"[{name}] ✅ Búsqueda/Entrenamiento Finalizado. Tiempo: {train_time:.2f}s")
    print(f"[{name}]   Mejor F1-CV (o train F1 si CV falló): {final_best_score:.4f} con Parámetros: {final_best_params}")

    # Asegurarse de que el estimador devuelto esté ajustado
    if not getattr(best_estimator, '_is_fitted', False) and hasattr(best_estimator, 'fit'):
         try:
             print(f"   Ajustando el best_estimator final para {name}...")
             best_estimator.fit(X_train, y_train)
         except Exception as final_fit_e:
              print(f"❌ ERROR FATAL al ajustar el best_estimator final para {name}: {final_fit_e}")
              return None, final_best_score, train_time

    return best_estimator, final_best_score, train_time


def find_best_threshold(y_true, y_scores, policies):
    """Encuentra el mejor umbral según políticas P/R y maximizando F1 sobre P-R curve."""
    # Validaciones de entrada robustas
    if not isinstance(y_true, np.ndarray) or not isinstance(y_scores, np.ndarray) or len(y_true) == 0 or len(y_scores) == 0:
         print("❌ ERROR: y_true o y_scores no válidos para find_best_threshold.")
         return config.DEFAULT_POLICY_NAME, config.DEFAULT_THRESHOLD, {config.DEFAULT_POLICY_NAME: config.DEFAULT_THRESHOLD}, {}
    if len(y_true) != len(y_scores):
         print(f"❌ ERROR: y_true ({len(y_true)}) y y_scores ({len(y_scores)}) tienen longitudes diferentes.")
         return config.DEFAULT_POLICY_NAME, config.DEFAULT_THRESHOLD, {config.DEFAULT_POLICY_NAME: config.DEFAULT_THRESHOLD}, {}
    if len(np.unique(y_true)) < 2:
         print("⚠️ ADVERTENCIA: y_true contiene solo una clase. No se puede calcular P-R curve. Usando umbral 0.5.")
         return config.DEFAULT_POLICY_NAME, config.DEFAULT_THRESHOLD, {config.DEFAULT_POLICY_NAME: config.DEFAULT_THRESHOLD}, {}

    try:
        precisions, recalls, thresholds = precision_recall_curve(y_true, y_scores)
        # thresholds tiene len = len(precisions) - 1. Añadir umbral > max(score) para el último punto.
        thresholds = np.append(thresholds, np.max(y_scores) + 1e-6 if len(y_scores)>0 else 1.0)

    except Exception as e:
        print(f"❌ ERROR en precision_recall_curve: {e}. Usando umbral 0.5.")
        return config.DEFAULT_POLICY_NAME, config.DEFAULT_THRESHOLD, {config.DEFAULT_POLICY_NAME: config.DEFAULT_THRESHOLD}, {}

    thresholds_map = {}
    metrics_at_thresholds = {}
    best_overall_f1 = -1.0
    best_policy_name = None

    print("\n--- Buscando Umbrales Óptimos (Continuos en P-R Curve) ---")
    # Iterar sobre cada punto de la curva P-R (cada threshold implícito)
    for i in range(len(thresholds)):
        th = thresholds[i]
        p = precisions[i]
        r = recalls[i]

        # Comprobar qué políticas cumple este punto
        for policy_name, reqs in policies.items():
            min_p = reqs['P_min']
            min_r = reqs['R_min']

            if p >= min_p and r >= min_r:
                # Calcular F1 para este punto
                f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

                # Si esta política aún no tiene un umbral O este F1 es mejor para ella
                if policy_name not in thresholds_map or f1 > metrics_at_thresholds[policy_name]['F1-Score']:
                    thresholds_map[policy_name] = float(th)
                    metrics_at_thresholds[policy_name] = {
                        'threshold': float(th), 'Precision': float(p),
                        'Recall': float(r), 'F1-Score': float(f1)
                    }

                    # Actualizar el mejor F1 GLOBAL encontrado que cumple *alguna* política
                    if f1 > best_overall_f1:
                        best_overall_f1 = f1
                        best_policy_name = policy_name

    # Reportar resultados finales por política
    print("\n--- Resultados de Búsqueda de Umbral por Política ---")
    for name, reqs in policies.items():
         if name in thresholds_map:
              metrics = metrics_at_thresholds[name]
              print(f"✅ Política '{name}' (P>={reqs['P_min']}, R>={reqs['R_min']}): Mejor Umbral={metrics['threshold']:.4f}, P={metrics['Precision']:.4f}, R={metrics['Recall']:.4f}, F1={metrics['F1-Score']:.4f}")
         else:
              print(f"❌ Política '{name}' (P>={reqs['P_min']}, R>={reqs['R_min']}) no pudo ser satisfecha.")
              # Añadir entrada placeholder si no se encontró
              thresholds_map[name] = None
              metrics_at_thresholds[name] = {'threshold': np.nan, 'Precision': np.nan, 'Recall': np.nan, 'F1-Score': np.nan}


    # Determinar el umbral final basado en la política con mejor F1 global
    if best_policy_name:
         final_threshold = thresholds_map[best_policy_name]
         final_metrics = metrics_at_thresholds[best_policy_name]
         print(f"\n🏆 POLÍTICA GANADORA (Mejor F1 global entre políticas satisfechas): '{best_policy_name}' con Umbral: {final_threshold:.4f}")
    else:
         # Fallback si ninguna política se cumple
         print(f"\n⚠️ ADVERTENCIA: Ninguna política pudo ser satisfecha. Usando umbral por defecto ({config.DEFAULT_THRESHOLD}).")
         best_policy_name = config.DEFAULT_POLICY_NAME
         final_threshold = config.DEFAULT_THRESHOLD
         thresholds_map[best_policy_name] = final_threshold # Añadir al mapa
         final_metrics = {'threshold': final_threshold, 'Precision': np.nan, 'Recall': np.nan, 'F1-Score': np.nan}
         metrics_at_thresholds[best_policy_name] = final_metrics # Añadir al mapa de métricas

    return best_policy_name, final_threshold, thresholds_map, metrics_at_thresholds

def train_and_evaluate_models(X_train, y_train, X_val, y_val, models_tune, models_no_tune, tuning_grids):
    """
    Entrena, afina (si aplica) y evalúa modelos en entrenamiento y validación.
    Devuelve DataFrame de resultados, dict de modelos entrenados y nombre del mejor modelo.
    """
    print(f"\n--- Iniciando Entrenamiento y Evaluación de {len(models_tune) + len(models_no_tune)} Modelos ---")
    results = []
    trained_models = {}
    best_f1_val = -1.0
    best_model_name = None

    all_models_config = {**models_tune, **models_no_tune} # Combinar todos

    for name, model in all_models_config.items():
        print(f"\n--- Procesando Modelo: {name} ---")
        model_pipeline = model # Asumir que ya es un pipeline o modelo base
        start_time = time()
        train_time = 0.0
        best_cv_score = np.nan

        try:
            if name in models_tune:
                # Afinar modelo
                grid = tuning_grids.get(name, {})
                best_estimator, best_cv_score, train_time = tune_model_with_cv(
                    model_pipeline, grid, X_train, y_train, name
                )
                if best_estimator is None: # Fallo total en tuning/fit
                    print(f"❌ Fallo crítico al afinar/ajustar {name}. Omitiendo.")
                    continue
                model_pipeline = best_estimator
            else:
                # Entrenar modelo base (sin afinar)
                print(f"[{name}] Ajustando modelo base (sin tuning)...")
                model_pipeline.fit(X_train, y_train)
                train_time = time() - start_time
                print(f"[{name}] ✅ Modelo base ajustado. Tiempo: {train_time:.2f}s")

            trained_models[name] = model_pipeline # Guardar el modelo ajustado (afinado o no)

            # --- Evaluación en Validación ---
            start_eval_time = time()
            if hasattr(model_pipeline, "predict_proba"):
                 y_scores_val = model_pipeline.predict_proba(X_val)[:, 1]
                 y_pred_val = (y_scores_val > 0.5).astype(int) # Umbral 0.5 para reporte inicial
            else: # Para modelos sin predict_proba (ej. SVM sin calibrar)
                 y_pred_val = model_pipeline.predict(X_val)
                 y_scores_val = y_pred_val # Usar predicciones como scores (no ideal)
            eval_time = time() - start_eval_time

            # Usar y_val, y_pred_val para reporte
            report_val = classification_report(y_val, y_pred_val, output_dict=True, zero_division=0)
            f1_val = report_val.get(str(config.EDA_TARGET_CLASS), {}).get('f1-score', 0.0)

            results.append({
                'Model': name,
                'F1 (Validation)': f1_val,
                'Precision (Validation)': report_val.get(str(config.EDA_TARGET_CLASS), {}).get('precision', 0.0),
                'Recall (Validation)': report_val.get(str(config.EDA_TARGET_CLASS), {}).get('recall', 0.0),
                'F1 (CV-Train)': best_cv_score, # F1 de CV o NaN si no se afinó
                'Train Time (s)': train_time,
                'Eval Time (s)': eval_time
            })

            print(f"[{name}]   Evaluación (Validación, Th=0.5): F1={f1_val:.4f}")

            if f1_val > best_f1_val:
                best_f1_val = f1_val
                best_model_name = name

        except Exception as e:
            print(f"❌ ERROR FATAL procesando el modelo {name}: {e}")
            import traceback
            traceback.print_exc() # Imprimir stack trace completo

    if not results:
         print("❌ No se pudo entrenar/evaluar ningún modelo.")
         return pd.DataFrame(), {}, None

    results_df = pd.DataFrame(results).sort_values(by='F1 (Validation)', ascending=False).reset_index(drop=True)

    print("\n--- Resumen de Evaluación de Modelos (en Validación, Th=0.5) ---")
    print(results_df.to_string())

    return results_df, trained_models, best_model_name

# --- Nueva Función para Selección de Umbral Discreto ---
def find_best_threshold_discrete(y_true, y_scores, policies, candidate_thresholds, priority_policy_name=None):
    """
    Encuentra el umbral MÁS ALTO de una lista discreta que cumple
    con las políticas P/R, priorizando una política específica si se indica.

    Args:
        y_true (np.ndarray): Etiquetas verdaderas.
        y_scores (np.ndarray): Puntuaciones de probabilidad del modelo.
        policies (dict): Diccionario con políticas {nombre: {'P_min': val, 'R_min': val}}.
        candidate_thresholds (list): Lista de umbrales a probar (ej. [0.95, 0.90, 0.85, 0.80]).
                                    ¡IMPORTANTE! Debe estar ordenada de MAYOR a MENOR.
        priority_policy_name (str, optional): Nombre de la política a intentar satisfacer primero. Defaults to None.

    Returns:
        tuple: (
            best_policy_name (str): Nombre de la política final seleccionada.
            final_best_threshold (float): Umbral seleccionado.
            thresholds_map (dict): Mapa con el umbral seleccionado {best_policy_name: final_best_threshold}.
            metrics_at_threshold (dict): Métricas (P, R, F1) en el umbral seleccionado.
        )
    """
    # Importar dependencias dentro de la función por si utils se carga antes
    import numpy as np
    import pandas as pd
    from sklearn.metrics import classification_report
    try:
        import config # Asume que config.py está accesible
    except ImportError:
        # Fallback si config no se puede importar directamente
        print("Fallback: Usando valores por defecto para config en find_best_threshold_discrete")
        class ConfigFallback:
            DEFAULT_POLICY_NAME = 'Default_0_5'
            DEFAULT_THRESHOLD = 0.5
            EDA_TARGET_CLASS = '1' # Asegúrate que esto coincida con tu config
        config = ConfigFallback()


    best_policy_name_found = config.DEFAULT_POLICY_NAME
    final_best_threshold_found = config.DEFAULT_THRESHOLD
    metrics_at_selected_threshold = {'threshold': config.DEFAULT_THRESHOLD, 'Precision': np.nan, 'Recall': np.nan, 'F1-Score': np.nan}
    found_threshold = False

    # Validaciones básicas
    if not isinstance(y_true, np.ndarray) or not isinstance(y_scores, np.ndarray) or len(y_true) == 0 or len(y_scores) == 0:
        print("❌ ERROR find_best_threshold_discrete: y_true o y_scores no válidos.")
        return best_policy_name_found, final_best_threshold_found, {best_policy_name_found: final_best_threshold_found}, metrics_at_selected_threshold
    if len(y_true) != len(y_scores):
        print(f"❌ ERROR find_best_threshold_discrete: y_true ({len(y_true)}) y y_scores ({len(y_scores)}) tienen longitudes diferentes.")
        return best_policy_name_found, final_best_threshold_found, {best_policy_name_found: final_best_threshold_found}, metrics_at_selected_threshold
    if len(np.unique(y_true)) < 2:
         print("⚠️ find_best_threshold_discrete: y_true contiene solo una clase. Usando umbral 0.5.")
         return best_policy_name_found, final_best_threshold_found, {best_policy_name_found: final_best_threshold_found}, metrics_at_selected_threshold

    print(f"Buscando el umbral MÁS ALTO en {candidate_thresholds} que cumpla las políticas...")

    # --- Intento 1: Priorizar política específica (si se proporcionó) ---
    if priority_policy_name and priority_policy_name in policies:
        print(f"--- Priorizando política: {priority_policy_name} ---")
        min_p_priority = policies[priority_policy_name]['P_min']
        min_r_priority = policies[priority_policy_name]['R_min']
        for th in candidate_thresholds: # Iterar de mayor a menor
            try:
                y_pred_th = (y_scores > th).astype(int)
                report_th = classification_report(y_true, y_pred_th, output_dict=True, zero_division=0)
                # Asegurarse que la clase objetivo exista en el reporte
                metrics_class_1 = report_th.get(str(config.EDA_TARGET_CLASS), None)
                if metrics_class_1 is None:
                    print(f"   ⚠️ Umbral {th:.2f}: Clase '{config.EDA_TARGET_CLASS}' no encontrada en reporte. Saltando.")
                    continue

                precision_th = metrics_class_1.get('precision', 0.0)
                recall_th = metrics_class_1.get('recall', 0.0)
                f1_th = metrics_class_1.get('f1-score', 0.0)

                if precision_th >= min_p_priority and recall_th >= min_r_priority:
                    final_best_threshold_found = th
                    best_policy_name_found = priority_policy_name
                    metrics_at_selected_threshold = {'threshold': th, 'Precision': precision_th, 'Recall': recall_th, 'F1-Score': f1_th}
                    print(f"✅ Encontrado umbral {th:.2f} que cumple {best_policy_name_found} (P={precision_th:.4f}, R={recall_th:.4f})")
                    found_threshold = True
                    break # Encontrado el más alto para la política prioritaria
            except Exception as e_th:
                print(f"   ⚠️ Error calculando métricas para umbral {th:.2f}: {e_th}")
                continue

    # --- Intento 2: Buscar en otras políticas si la prioritaria falló o no se especificó ---
    if not found_threshold:
        if priority_policy_name:
            print(f"--- Política prioritaria '{priority_policy_name}' no satisfecha. Buscando en otras políticas... ---")
        else:
            print(f"--- Buscando en todas las políticas (sin prioridad)... ---")

        for th in candidate_thresholds: # Iterar de mayor a menor
            try:
                y_pred_th = (y_scores > th).astype(int)
                report_th = classification_report(y_true, y_pred_th, output_dict=True, zero_division=0)
                metrics_class_1 = report_th.get(str(config.EDA_TARGET_CLASS), None)
                if metrics_class_1 is None:
                    print(f"   ⚠️ Umbral {th:.2f}: Clase '{config.EDA_TARGET_CLASS}' no encontrada en reporte. Saltando.")
                    continue

                precision_th = metrics_class_1.get('precision', 0.0)
                recall_th = metrics_class_1.get('recall', 0.0)
                f1_th = metrics_class_1.get('f1-score', 0.0)

                # Iterar sobre las políticas (excluyendo la prioritaria si ya se chequeó)
                policy_satisfied_this_th = None
                for policy_name, reqs in policies.items():
                    if priority_policy_name and policy_name == priority_policy_name:
                        continue
                    if precision_th >= reqs['P_min'] and recall_th >= reqs['R_min']:
                        policy_satisfied_this_th = policy_name
                        break # Encontró una política que cumple

                if policy_satisfied_this_th:
                    final_best_threshold_found = th
                    best_policy_name_found = policy_satisfied_this_th
                    metrics_at_selected_threshold = {'threshold': th, 'Precision': precision_th, 'Recall': recall_th, 'F1-Score': f1_th}
                    print(f"✅ Encontrado umbral {th:.2f} que cumple {best_policy_name_found} (P={precision_th:.4f}, R={recall_th:.4f})")
                    found_threshold = True
                    break # Encontrado el más alto que cumple *alguna* política
            except Exception as e_th_other:
                print(f"   ⚠️ Error calculando métricas para umbral {th:.2f} (otras políticas): {e_th_other}")
                continue

    # --- Fallback al umbral por defecto ---
    if not found_threshold:
        print(f"⚠️ Ningún umbral candidato en {candidate_thresholds} cumplió alguna política. Usando umbral por defecto ({config.DEFAULT_THRESHOLD}).")
        final_best_threshold_found = config.DEFAULT_THRESHOLD
        best_policy_name_found = config.DEFAULT_POLICY_NAME
        # Calcular métricas para 0.5 si es posible
        try:
             y_pred_default = (y_scores > config.DEFAULT_THRESHOLD).astype(int)
             report_default = classification_report(y_true, y_pred_default, output_dict=True, zero_division=0)
             metrics_class_1_default = report_default.get(str(config.EDA_TARGET_CLASS), {})
             metrics_at_selected_threshold = {
                 'threshold': config.DEFAULT_THRESHOLD,
                 'Precision': metrics_class_1_default.get('precision', np.nan),
                 'Recall': metrics_class_1_default.get('recall', np.nan),
                 'F1-Score': metrics_class_1_default.get('f1-score', np.nan)
             }
        except Exception as e_rep_def:
             print(f"   No se pudieron calcular métricas para el umbral {config.DEFAULT_THRESHOLD}: {e_rep_def}")
             # metrics_at_selected_threshold ya tiene NaNs

    # Crear el 'thresholds_map' final (solo contiene el umbral elegido)
    thresholds_map_final = {best_policy_name_found: final_best_threshold_found}

    return best_policy_name_found, final_best_threshold_found, thresholds_map_final, metrics_at_selected_threshold
# --- Fin Nueva Función ---

def clean_numpy_types(obj):
    """Convierte tipos numpy a tipos nativos de Python recursivamente para JSON."""
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        if np.isnan(obj): return None # Convertir NaN a None
        if np.isinf(obj): return None # Convertir Inf a None
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist() # Convertir arrays a listas
    elif isinstance(obj, dict):
        # Recursión para diccionarios
        return {k: clean_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        # Recursión para listas/tuplas
        return [clean_numpy_types(item) for item in obj]
    elif isinstance(obj, (bool, np.bool_)):
        return bool(obj)
    else:
        # Devolver el objeto tal cual si no es un tipo numpy o contenedor
        return obj
    
    
# --- Funciones de Guardado ---
def save_artifact(artifact, path):
    """Guarda un artefacto (modelo, scaler, encoder) usando joblib."""
    if artifact is None:
        print(f"⚠️ No se guardó artefacto en {path} porque es None.")
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(artifact, path)
        print(f"✅ Artefacto guardado en: {path}")
    except Exception as e:
        print(f"❌ ERROR al guardar artefacto en {path}: {e}")

def save_metrics_json(metrics_dict, path):
    """Guarda un diccionario de métricas como JSON, limpiando tipos numpy."""
    if metrics_dict is None:
        print(f"⚠️ No se guardaron métricas en {path} porque el diccionario es None.")
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Limpiar tipos antes de guardar
        cleaned_metrics = clean_numpy_types(metrics_dict)
        with open(path, 'w') as f:
            json.dump(cleaned_metrics, f, indent=4)
        print(f"✅ Métricas guardadas en: {path}")
    except TypeError as te:
         print(f"❌ ERROR de tipo al convertir métricas a JSON en {path}: {te}")
         print("   Diccionario problemático (parcial):", str(metrics_dict)[:500]) # Imprimir parte para depurar
    except Exception as e:
        print(f"❌ ERROR inesperado al guardar métricas JSON en {path}: {e}")

def save_dataframe_csv(df, path):
    """Guarda un DataFrame como CSV."""
    if df is None or df.empty:
        print(f"⚠️ No se guardó DataFrame en {path} porque es None o está vacío.")
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        df.to_csv(path, index=False)
        print(f"✅ DataFrame guardado en: {path}")
    except Exception as e:
        print(f"❌ ERROR al guardar DataFrame CSV en {path}: {e}")

print("✅ Archivo utils.py listo y funciones definidas.")
