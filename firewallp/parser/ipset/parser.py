from lxml import etree


def __recursive_elements(element):
    returned_json = dict()
    if element.getchildren():
        for subelement in element.iterchildren("*"):
            if subelement.tag in 'members':
                l = []
                for member in subelement.findall('.//elem'):
                    l.append(member.text)
                returned_json.update({subelement.tag: l})
            else:
                if subelement.attrib:
                    returned_json.update({subelement.attrib['name']: __recursive_elements(subelement)})
                else:
                    returned_json.update(__recursive_elements(subelement))
    else:
        if '\n' not in element.text:
            returned_json.update({element.tag: element.text})
    return returned_json


def get_xml_to_dic(xml):
    root = etree.XML(xml)
    tree = etree.ElementTree(root)
    return __recursive_elements(tree.getroot())
