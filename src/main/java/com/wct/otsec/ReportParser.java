package com.wct.otsec;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.stereotype.Component;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import java.io.StringReader;
import org.xml.sax.InputSource;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class ReportParser {
    static final int MAX_BYTES=5*1024*1024, MAX_RECORDS=10000;
    final JsonMapper json=JsonMapper.builder().build();
    record Finding(String title,String severity,String resource,String rule,String description,String solution) {}
    static String text(String value,int limit) {
        if(value==null || value.length()>limit*4) throw new IllegalArgumentException("Invalid report text length");
        String clean=value.replaceAll("<[^>]*>","").strip(); return clean.substring(0,Math.min(clean.length(),limit));
    }
    static String field(JsonNode node,String key,String fallback) {
        JsonNode value=node.get(key);
        if(value==null && fallback!=null) return fallback;
        if(value==null || !value.isString()) throw new IllegalArgumentException("Expected text field: "+key);
        return value.asString();
    }
    static Iterable<JsonNode> list(JsonNode node) {
        if(node==null || !node.isArray() || node.size()>MAX_RECORDS) throw new IllegalArgumentException("Expected bounded report list");
        for(JsonNode row:node) if(!row.isObject()) throw new IllegalArgumentException("Expected report objects");
        return node;
    }
    static String number(JsonNode node,String key) {
        JsonNode value=node.get(key);
        if(value==null || (!value.isString() && !value.isIntegralNumber())) throw new IllegalArgumentException("Invalid numeric identifier");
        return value.asText();
    }
    static String message(Element element,String tag,String fallback) {
        var nodes=element.getElementsByTagName(tag); return nodes.getLength()==0 ? fallback : nodes.item(0).getTextContent();
    }
    static void add(List<Finding> rows,String title,String severity,String resource,String rule,String description,String solution) {
        if(rows.size()>=MAX_RECORDS) throw new IllegalArgumentException("Too many findings");
        String t=text(title,240), r=text(rule,240), s=text(severity,30).toUpperCase(Locale.ROOT);
        if(t.isEmpty() || r.isEmpty()) throw new IllegalArgumentException("Empty finding identifier");
        if(!Set.of("CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN").contains(s)) s="UNKNOWN";
        rows.add(new Finding(t,s,text(resource,500),r,text(description,2000),text(solution,2000)));
    }
    static void bounded(String content) {
        if(content==null || content.isEmpty() || content.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES) throw new IllegalArgumentException("Report must be between 1 byte and 5 MiB");
    }
    public List<Finding> parse(String tool,String content) {
        bounded(content); List<Finding> rows=new ArrayList<>();
        try {
            if(content.startsWith("\uFEFF")) content=content.substring(1);
            if(Set.of("spotbugs","find-sec-bugs").contains(tool)) {
                var factory=DocumentBuilderFactory.newInstance();
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
                factory.setFeature("http://xml.org/sax/features/external-general-entities",false);
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
                factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD,""); factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA,"");
                factory.setXIncludeAware(false); factory.setExpandEntityReferences(false);
                var root=factory.newDocumentBuilder().parse(new InputSource(new StringReader(content))).getDocumentElement();
                if(!root.getTagName().equals("BugCollection")) throw new IllegalArgumentException();
                var bugs=root.getChildNodes();
                for(int i=0;i<bugs.getLength();i++) if(bugs.item(i) instanceof Element bug && bug.getTagName().equals("BugInstance")) {
                    String severity=Map.of("1","HIGH","2","MEDIUM","3","LOW").get(bug.getAttribute("priority"));
                    if(severity==null) throw new IllegalArgumentException();
                    var classes=bug.getElementsByTagName("Class");
                    String resource=classes.getLength()==0 ? "unknown" : ((Element)classes.item(0)).getAttribute("classname");
                    add(rows,message(bug,"LongMessage",message(bug,"ShortMessage",bug.getAttribute("type"))),severity,resource,bug.getAttribute("type"),"","");
                }
            } else {
                JsonNode root=json.readTree(content);
                if(root==null || !root.isObject()) throw new IllegalArgumentException();
                switch(tool) {
                    case "zaproxy" -> { for(JsonNode site:list(root.get("site"))) {
                        URI uri=new URI(field(site,"@name",null));
                        if(!Set.of("http","https").contains(uri.getScheme()) || uri.getHost()==null || uri.getPort()>65535) throw new IllegalArgumentException();
                        String resource=new URI(uri.getScheme(),null,uri.getHost(),uri.getPort(),uri.getPath(),null,null).toString();
                        for(JsonNode alert:list(site.get("alerts"))) {
                            String severity=Map.of("0","INFO","1","LOW","2","MEDIUM","3","HIGH").get(number(alert,"riskcode"));
                            if(severity==null) throw new IllegalArgumentException();
                            add(rows,field(alert,"name",field(alert,"alert","")),severity,resource,number(alert,"pluginid"),field(alert,"desc",""),field(alert,"solution",""));
                        }
                    }}
                    case "dependency-check" -> { for(JsonNode dependency:list(root.get("dependencies"))) {
                        JsonNode vulnerabilities=dependency.get("vulnerabilities");
                        if(vulnerabilities==null) continue;
                        for(JsonNode v:list(vulnerabilities)) add(rows,field(v,"name",null),field(v,"severity","UNKNOWN"),field(dependency,"fileName",null),field(v,"name",null),field(v,"description",""),"Review the dependency and upgrade to a verified unaffected version.");
                    }}
                    case "sonarqube" -> { for(JsonNode issue:list(root.get("issues"))) add(rows,field(issue,"message",null),Map.of("BLOCKER","CRITICAL","CRITICAL","HIGH","MAJOR","MEDIUM","MINOR","LOW","INFO","INFO").getOrDefault(field(issue,"severity",""),"UNKNOWN"),field(issue,"component",null),field(issue,"rule",null),"",""); }
                    default -> throw new IllegalArgumentException();
                }
            }
            return rows;
        } catch(Exception e) { throw new IllegalArgumentException("Invalid or unsupported report; no findings imported"); }
    }
}
