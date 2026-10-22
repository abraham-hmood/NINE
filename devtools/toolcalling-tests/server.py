import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
LOG = open('/tmp/e2e/requests.log','w')
state = {}
BUG = 'Creating the extension now.\ntool write_all_files files=extensions/helloworld/nine-extension.json|||{"id": "com.helloworld.example","name":"Hello World Extension", "version" : "1.0.0", "entry": "com.example.helloworld.MainActivity"}--extensions/helloworld/AndroidManifest.xml|||<manifest package="com.helloworld.example"/>\ntool compile_extension project_path=extensions/helloworld'
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        scen = self.path.split('/')[1]
        LOG.write(json.dumps({"scen":scen,"has_tools":"tools" in body,"roles":[m["role"] for m in body["messages"]]})+"\n"); LOG.flush()
        msgs = body["messages"]
        got_result = any(m["role"]=="tool" or (m["role"]=="user" and m["content"].startswith("TOOL RESULTS")) for m in msgs)
        def reply(msg, code=200):
            out = json.dumps(msg).encode(); self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
        def text(t): reply({"choices":[{"message":{"role":"assistant","content":t}}]})
        if scen == "native":
            if not got_result:
                reply({"choices":[{"message":{"role":"assistant","content":None,"tool_calls":[
                  {"id":"call_9","type":"function","function":{"name":"write_file","arguments":json.dumps({"path":"native/a.txt","content":"from native"})}}]}}]})
            else:
                text("All done (native).")
        elif scen == "textonly":      # API that rejects `tools`
            if "tools" in body: reply({"error":{"message":"Unrecognized request argument: tools"}}, 400)
            elif not got_result: text(BUG)
            else: text("All done (text).")
        elif scen == "ignores":       # accepts `tools` but answers in a text dialect anyway
            if not got_result: text('<tool_call>\n{"name":"write_file","arguments":{"path":"ign/b.txt","content":"from hermes"}}\n</tool_call>')
            else: text("All done (ignores).")
        elif scen == "loop":          # never stops calling the same tool
            text('```tool list_files\npath=.\n```')
        else: text("hi")
HTTPServer(('127.0.0.1',8765),H).serve_forever()
