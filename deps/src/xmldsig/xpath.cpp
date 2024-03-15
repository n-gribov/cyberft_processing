#include <libxml/parser.h>
#include <libxml/xpath.h>

// xpath example.xml "//*[local-name()='Signature']"
// "/*/*/*[local-name()='Signature'][2]"

xmlDocPtr getdoc (char *docname) {
    xmlDocPtr doc;
    doc = xmlParseFile(docname);

    if (doc == NULL ) {
        fprintf(stderr,"Document not parsed successfully. \n");
        return NULL;
    }

    return doc;
}

xmlXPathObjectPtr getnodeset (xmlDocPtr doc, xmlChar *xpath){

    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;

    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        printf("Error in xmlXPathNewContext\n");
        return NULL;
    }
    result = xmlXPathEvalExpression(xpath, context);
    xmlXPathFreeContext(context);
    if (result == NULL) {
        printf("Error in xmlXPathEvalExpression\n");
        return NULL;
    }
    if(xmlXPathNodeSetIsEmpty(result->nodesetval)){
        xmlXPathFreeObject(result);
        printf("No result\n");
        return NULL;
    }
    return result;
}

int main(int argc, char **argv) {

    char *docname;
    xmlNodePtr cur;
    xmlDocPtr doc;
    xmlNodeSetPtr nodes;
    xmlXPathObjectPtr result;
    int i;
    //xmlChar *keyword;

    if (argc < 3) {
        printf("Usage: xpath <xmlfile> <XPath>\n");
        return -1;
    }

    docname = argv[1];
    doc = getdoc(docname);
    result = getnodeset (doc, (xmlChar *) argv[2]);
    if (result) {
        nodes = result->nodesetval;
        printf("items count: %i\n", nodes->nodeNr);
        for (i=0; i < nodes->nodeNr; i++) {
            /*
               keyword = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
               printf("keyword: %s\n", keyword);
               xmlFree(keyword);
               */
            if(nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
                xmlNsPtr ns;

                ns = (xmlNsPtr)nodes->nodeTab[i];
                cur = (xmlNodePtr)ns->next;
                if(cur->ns) { 
                    printf("= namespace \"%s\"=\"%s\" for node %s:%s\n", 
                            ns->prefix, ns->href, cur->ns->href, cur->name);
                } else {
                    printf("= namespace \"%s\"=\"%s\" for node %s\n", 
                            ns->prefix, ns->href, cur->name);
                }
            } else if(nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
                cur = nodes->nodeTab[i];        
                if(cur->ns) { 
                    printf("= element node \"%s:%s\"\n", 
                            cur->ns->href, cur->name);
                } else {
                    printf("= element node \"%s\"\n", 
                            cur->name);
                }
            } else {
                cur = nodes->nodeTab[i];    
                printf("= node \"%s\": type %d\n", cur->name, cur->type);
            }
        }
        xmlXPathFreeObject (result);
    }
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}

