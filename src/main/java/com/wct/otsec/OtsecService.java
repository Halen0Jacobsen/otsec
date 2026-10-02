package com.wct.otsec;

import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.core.io.ClassPathResource;
import tools.jackson.databind.JsonNode;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
public class OtsecService {
    private final JdbcTemplate db;
    private final ReportParser parser;
    private final List<Map<String,Object>> tools;
    @SuppressWarnings("unchecked")
    OtsecService(JdbcTemplate db,ReportParser parser) throws Exception {
        this.db=db; this.parser=parser;
        try(var input=new ClassPathResource("tools.json").getInputStream()) { tools=parser.json.readValue(input,List.class); }
    }
    static String label(String value) {
        if(value==null || value.isBlank() || value.length()>120 || value.chars().anyMatch(c -> c<32)) throw new IllegalArgumentException("Use 1–120 printable characters");
        return value.strip();
    }
    static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(Exception e) { throw new IllegalStateException(e); }
    }
    private String now() { return Instant.now().toString(); }
    private void audit(String action,String resource,String result) {
        var auth=SecurityContextHolder.getContext().getAuthentication();
        String actor=auth==null || auth.getName().equals("anonymousUser") ? "local-operator" : auth.getName();
        db.update("INSERT INTO audit(actor,action,resource,result,timestamp) VALUES(?,?,?,?,?)",actor,action,resource,result,now());
    }
    private Map<String,Object> env(String name) {
        var rows=db.queryForList("SELECT * FROM environments WHERE name=?",label(name));
        if(rows.isEmpty()) throw new IllegalArgumentException("Unknown environment"); return rows.getFirst();
    }
    @Transactional public Map<String,Object> environment(String name,String mode,String cidr) {
        name=label(name); Scope.parse(cidr);
        if(!Set.of("lab","production").contains(mode==null?"":mode)) throw new IllegalArgumentException("Mode must be lab or production");
        String id=UUID.randomUUID().toString();
        db.update("INSERT INTO environments VALUES(?,?,?,?)",id,name,mode,cidr);
        audit("environment.create",id,"success"); return env(name);
    }
    @Transactional public Map<String,Object> plan(String environment,String tool,String action,String target) {
        var env=env(environment); target=Scope.literal(label(target));
        if(!Scope.parse((String)env.get("cidr")).contains(target)) throw new IllegalArgumentException("Target is outside the environment allowlist");
        if(!(Objects.equals(tool,"zaproxy") && Objects.equals(action,"scan") || Objects.equals(tool,"custom") && Objects.equals(action,"remediate"))) throw new IllegalArgumentException("Adapter does not support this action");
        String id=UUID.randomUUID().toString(), state=env.get("mode").equals("production") && action.equals("scan") ? "blocked-by-policy" : "proposed";
        db.update("INSERT INTO plans VALUES(?,?,?,?,?,?,?)",id,env.get("id"),tool,action,target,state,now());
        audit("plan.create",id,state); return Map.of("id",id,"state",state,"executed",false);
    }
    @Transactional public Map<String,Object> evidence(String environment,String tool,String application,String content) {
        var env=env(environment); ReportParser.bounded(content);
        // Serialize imports per environment so deduplication remains atomic across concurrent requests.
        db.queryForList("SELECT id FROM environments WHERE id=? FOR UPDATE",env.get("id"));
        if(Objects.equals(tool,"zeek")) return zeek(env,content);
        application=label(application); var rows=parser.parse(tool,content); int imported=0;
        for(var row:rows) {
            String id=hash(parser.json.writeValueAsString(List.of(env.get("id"),tool,application,row)));
            if(db.queryForObject("SELECT count(*) FROM findings WHERE id=?",Integer.class,id)>0) continue;
            db.update("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)",id,env.get("id"),tool,application,row.title(),row.severity(),row.resource(),row.rule(),row.description(),row.solution(),now()); imported++;
        }
        String id=UUID.randomUUID().toString();
        db.update("INSERT INTO report_imports VALUES(?,?,?,?,?,?,?)",id,env.get("id"),tool,application,imported,rows.size()-imported,now());
        audit("report.import",id,"imported:"+imported+";duplicates:"+(rows.size()-imported));
        return Map.of("imported",imported,"duplicates",rows.size()-imported,"report_id",id);
    }
    record Connection(double ts,String src,String dst,int port,String service) {}
    private Map<String,Object> zeek(Map<String,Object> env,String content) {
        Scope scope=Scope.parse((String)env.get("cidr")); List<Connection> rows=new ArrayList<>();
        try {
            for(String line:content.split("\\R")) {
                if(line.isBlank()) continue;
                if(line.length()>65536 || rows.size()>=ReportParser.MAX_RECORDS) throw new IllegalArgumentException();
                JsonNode row=parser.json.readTree(line);
                String src=Scope.literal(ReportParser.field(row,"id.orig_h",null)),dst=Scope.literal(ReportParser.field(row,"id.resp_h",null));
                JsonNode ts=row.get("ts"), port=row.get("id.resp_p");
                if(ts==null || !ts.isNumber() || !Double.isFinite(ts.asDouble()) || ts.asDouble()<0 || ts.asDouble()>253402300799d || port==null || !port.isIntegralNumber() || !port.canConvertToInt() || port.asInt()<0 || port.asInt()>65535 || !scope.contains(src) && !scope.contains(dst)) throw new IllegalArgumentException();
                rows.add(new Connection(ts.asDouble(),src,dst,port.asInt(),label(ReportParser.field(row,"service","unknown"))));
            }
            if(rows.isEmpty()) throw new IllegalArgumentException();
        } catch(Exception e) { throw new IllegalArgumentException("Invalid Zeek import; no records imported"); }
        int imported=0;
        for(Connection row:rows) {
            String id=hash(parser.json.writeValueAsString(List.of(env.get("id"),row)));
            if(db.queryForObject("SELECT count(*) FROM observations WHERE id=?",Integer.class,id)>0) continue;
            db.update("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)",id,env.get("id"),row.ts(),row.src(),row.dst(),row.port(),row.service(),scope.contains(row.src()) && scope.contains(row.dst()) ? 0:1); imported++;
            for(String ip:List.of(row.src(),row.dst())) if(scope.contains(ip)) {
                int changed=db.update("UPDATE assets SET first_seen=LEAST(first_seen,?),last_seen=GREATEST(last_seen,?) WHERE environment_id=? AND ip=?",row.ts(),row.ts(),env.get("id"),ip);
                if(changed==0) db.update("INSERT INTO assets VALUES(?,?,?,?)",env.get("id"),ip,row.ts(),row.ts());
            }
        }
        audit("zeek.import",(String)env.get("id"),"imported:"+imported+";duplicates:"+(rows.size()-imported));
        return Map.of("imported",imported,"duplicates",rows.size()-imported);
    }
    @Transactional(readOnly=true) public Map<String,Object> snapshot() {
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("environments",db.queryForList("SELECT * FROM environments ORDER BY name")); result.put("tools",tools);
        for(String table:List.of("assets","observations","plans","findings","report_imports")) {
            String order=switch(table) { case "assets" -> "e.name,t.ip"; case "observations" -> "t.ts DESC"; case "plans" -> "t.created_at DESC"; default -> "t.imported_at DESC"; };
            result.put(table,db.queryForList("SELECT t.*,e.name environment FROM "+table+" t JOIN environments e ON e.id=t.environment_id ORDER BY "+order+" LIMIT "+(Set.of("assets","findings").contains(table)?500:100)));
        }
        result.put("audit",db.queryForList("SELECT * FROM audit ORDER BY id DESC LIMIT 100"));
        Map<String,Object> counts=new LinkedHashMap<>(),severities=new LinkedHashMap<>();
        for(String table:List.of("assets","observations","plans","environments","findings","report_imports")) counts.put(table,db.queryForObject("SELECT count(*) FROM "+table,Long.class));
        db.query("SELECT severity,count(*) total FROM findings GROUP BY severity",rs -> { severities.put(rs.getString("severity"),rs.getLong("total")); });
        result.put("counts",counts); result.put("severity_counts",severities); return result;
    }
}
