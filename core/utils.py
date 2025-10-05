import os


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

fields_order, fields = load_fields()
#print(fields_order)
#print(fields)
#raise Exception('stop')
