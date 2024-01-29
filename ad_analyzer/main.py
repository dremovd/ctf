from fastapi import FastAPI, UploadFile, File
from typing import List
import os.path
from analyzer import analyze_file
from description import File as FileDescriptor

UPLOAD_DIR = 'uploads'
app = FastAPI()

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    contents = await file.read()
    contents = contents.decode()
    name = os.path.basename(file.filename)
    extension = os.path.splitext(name)[1]
    lines_count = contents.count('\n')
    upload_filename = os.path.join(UPLOAD_DIR, name)
    
    with open(upload_filename, 'w') as f:
        f.write(contents)

    lines_count = len(contents.split('\n'))
    file_descriptor = FileDescriptor(UPLOAD_DIR, name, lines_count, extension, is_binary=False)
    file_vulnerabilities = analyze_file(
        UPLOAD_DIR, 
        file_descriptor, 
        [],
        debug=True
    )
    for file_vulnerability in file_vulnerabilities:
        print(file_vulnerability)
        print()
    
    return [v.as_dict() for v in file_vulnerabilities]
    #return FileResponse(upload_filename, media_type='text/html')
