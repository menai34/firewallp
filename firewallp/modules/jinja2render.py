from jinja2 import Environment, FileSystemLoader
import os


def __render_iptables_rules(path, context):
    path, filename = os.path.split(path)
    return Environment(loader=FileSystemLoader(path or './')).get_template(filename).render(context)


def __write_to_file(output_file, data):
    with open(output_file, 'w') as f:
        f.write(data)
