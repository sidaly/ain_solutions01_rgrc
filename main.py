import os 

import sqlite3 

import hashlib 

import asyncio 

from fastapi import FastAPI, File, UploadFile, HTTPException 

from fastapi.middleware.cors import CORSMiddleware 

from pydantic import BaseModel 

from typing import Optional 

from virustotal_python import Virustotal 

from dotenv import load_dotenv 

from datetime import datetime 

 

load_dotenv() 

 

app = FastAPI() 

app.add_middleware( 

CORSMiddleware, 

allow_origins=["http://localhost:3000"], 

allow_credentials=True, 

allow_methods=["*"], 

allow_headers=["*"], 

) 

 

# Initialize VirusTotal client 

vtotal = Virustotal(os.getenv("VIRUSTOTAL_API_KEY")) 

 

# SQLite database setup 

conn = sqlite3.connect("scans.db") 

cursor = conn.cursor() 

cursor.execute(""" 

CREATE TABLE IF NOT EXISTS scans ( 

id INTEGER PRIMARY KEY AUTOINCREMENT, 

resource_type TEXT, 

resource_id TEXT, 

result TEXT, 

scan_date TEXT 

) 

""") 

conn.commit() 

 

class ScanRequest(BaseModel): 

url: Optional[str] = None 

ip: Optional[str] = None 

 

def calculate_file_hash(file: UploadFile): 

sha256 = hashlib.sha256() 

for chunk in iter(lambda: file.file.read(65536), b""): 

sha256.update(chunk) 

file.file.seek(0) 

return sha256.hexdigest() 

 

@app.post("/api/scan/file") 

async def scan_file(file: UploadFile = File(...)): 

try: 

file_hash = calculate_file_hash(file) 

# Check if file exists in VirusTotal 

resp = await asyncio.to_thread(vtotal.request, f"files/{file_hash}") 

if resp.status_code == 200: 

result = resp.data 

cursor.execute( 

"INSERT INTO scans (resource_type, resource_id, result, scan_date) VALUES (?, ?, ?, ?)", 

("file", file_hash, str(result), datetime.now().isoformat()) 

) 

conn.commit() 

return { 

"success": True, 

"resource_type": "file", 

"resource_id": file_hash, 

"stats": result["attributes"]["last_analysis_stats"], 

"results": result["attributes"]["last_analysis_results"] 

} 

 

# Upload file if not found 

files = {"file": (file.filename, file.file, file.content_type)} 

resp = await asyncio.to_thread(vtotal.request, "files", files=files, method="POST") 

analysis_id = resp.json()["data"]["id"] 

# Wait for analysis (simplified, add polling for production) 

await asyncio.sleep(10) 

resp = await asyncio.to_thread(vtotal.request, f"analyses/{analysis_id}") 

result = resp.json()["data"] 

cursor.execute( 

"INSERT INTO scans (resource_type, resource_id, result, scan_date) VALUES (?, ?, ?, ?)", 

("file", file_hash, str(result), datetime.now().isoformat()) 

) 

conn.commit() 

return { 

"success": True, 

"resource_type": "file", 

"resource_id": file_hash, 

"stats": result["attributes"]["stats"], 

"results": result["attributes"]["results"] 

} 

except Exception as e: 

raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}") 

 

@app.post("/api/scan/url") 

async def scan_url(request: ScanRequest): 

try: 

if not request.url: 

raise HTTPException(status_code=400, detail="URL is required") 

# Submit URL for scanning 

resp = await asyncio.to_thread(vtotal.request, "urls", data={"url": request.url}, method="POST") 

url_id = resp.json()["data"]["id"] 

# Wait for analysis 

await asyncio.sleep(10) 

resp = await asyncio.to_thread(vtotal.request, f"analyses/{url_id}") 

result = resp.json()["data"] 

cursor.execute( 

"INSERT INTO scans (resource_type, resource_id, result, scan_date) VALUES (?, ?, ?, ?)", 

("url", request.url, str(result), datetime.now().isoformat()) 

) 

conn.commit() 

return { 

"success": True, 

"resource_type": "url", 

"resource_id": request.url, 

"stats": result["attributes"]["stats"], 

"results": result["attributes"]["results"] 

} 

except Exception as e: 

raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}") 

 

@app.post("/api/scan/ip") 

async def scan_ip(request: ScanRequest): 

try: 

if not request.ip: 

raise HTTPException(status_code=400, detail="IP address is required") 

resp = await asyncio.to_thread(vtotal.request, f"ip_addresses/{request.ip}") 

result = resp.data 

cursor.execute( 

"INSERT INTO scans (resource_type, resource_id, result, scan_date) VALUES (?, ?, ?, ?)", 

("ip", request.ip, str(result), datetime.now().isoformat()) 

) 

conn.commit() 

return { 

"success": True, 

"resource_type": "ip", 

"resource_id": request.ip, 

"stats": result["attributes"]["last_analysis_stats"], 

"results": result["attributes"]["last_analysis_results"] 

} 

except Exception as e: 

raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}") 

 

@app.get("/api/scans") 

async def get_scans(): 

cursor.execute("SELECT * FROM scans ORDER BY scan_date DESC") 

rows = cursor.fetchall() 

return [ 

{ 

"id": row[0], 

"resource_type": row[1], 

"resource_id": row[2], 

"result": row[3], 

"scan_date": row[4] 

} for row in rows 

] 

 
