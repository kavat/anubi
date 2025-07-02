import os

from jinja2 import Environment, FileSystemLoader

def export_html(data, type):

  script_dir = os.path.dirname(os.path.abspath(__file__))
  template_dir = os.path.join(script_dir, 'templates')
  env = Environment(loader=FileSystemLoader(template_dir))

  template = env.get_template(f"./template_{type}.html")
  html_output = template.render(data=data)
  with open(f"./reports/output_{type}.html", 'w', encoding='utf-8') as f:
    f.write(html_output)

