import os


def load_keywords():
    keywords_file = os.getenv('KEYWORDS_FILE')
    if keywords_file is None:
        raise Exception("ERROR: KEYWORDS_FILE not set!")
    if not os.path.exists(keywords_file):
        raise Exception(f"ERROR: Keywords file '{keywords_file}' not found!")
    with open(keywords_file, 'r') as f:
        keywords = f.read().splitlines()
    return keywords


def load_fields():
    fields_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'fields.tsv')
    fields_order = []
    fields = {}
    with open(fields_file, 'r', encoding='utf-8') as f:
        header = f.readline().strip().split('\t')
        if len(header) != 3 or header[0] != 'key' or header[1] != 'name' or header[2] != 'description':
            raise Exception('Invalid fields file: ' + fields_file)

        for line in f.readlines():
            (key, name, description) = line.strip().split('\t')
            if key in fields:
                raise Exception('Duplicate key: ' + key)
            fields_order.append(key)
            fields[key] = {
                'name': name,
                'description': description,
            }

    return fields_order, fields

#fields_order, fields = load_fields()
#print(fields_order)
#print(fields)
#raise Exception('stop')


def generate_system_prompt():
    """动态生成 system prompt"""
    fields_order, fields = load_fields()
    
    # 基础 prompt 模板
    base_prompt = """You are an information extracting bot. You extracts key information of one scientific paper from provided title and abstract, and translate them into Chinese.

The extracted key information should be output in JSON format as:

{json_template}

Some criteria for the key information:

{criteria_list}
- If no any supported information in the title and abstract, output "NA" for the corresponding key.
- All values should be translated into Chinese, unless some abbr. that are clear enough to keep in English.
- Sentences should not have a period at the end.
"""
    
    # 生成 JSON 模板
    json_lines = ["{"]
    for field_key in fields_order:
        json_lines.append(f'  "{field_key}": "...",')
    json_lines.append("}")
    json_template = "\n".join(json_lines)
    
    # 生成字段描述列表
    criteria_lines = []
    for field_key in fields_order:
        field_info = fields[field_key]
        criteria_lines.append(f"- {field_key}: {field_info['description']}")
    criteria_list = "\n".join(criteria_lines)
    
    # 生成完整的 prompt
    full_prompt = base_prompt.format(
        json_template=json_template,
        criteria_list=criteria_list
    )
    
    return full_prompt
