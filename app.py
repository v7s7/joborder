import os
import glob
import json
import win32com.client as win32
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder='web', static_url_path='')

# -------------------------
# CONFIGURATION
# -------------------------
TEMPLATE_FILE = "Job work order.xlsx"
OUTPUT_FOLDER = "Generated_Reports"

# --- EXISTING MAPPINGS ---
JOB_NO_CELL = "C3"
DATE_MAP = {"main_date": "H3", "start_date": "E11", "end_date": "N11"}
CELL_MAP = {"engineer": "E12", "head_section": "N12"}
LABELED_FIELDS = {"description": "A4", "objective": "A6", "note": "A10", "remarks": "A14"}
TYPE_MAPPING = {"Site": "site", "Office": "office"}
TO_SECTION_MAPPING = {
    "servies": "servies", "Design": "Design", "project": "project",
    "QS": "QS", "Mosque Maint.": "Mosque Maint.",
    "Investment Maint.": "Investment Maint.", "Cemetry": "Cemetry",
    "MEP": "MEP", "Others": "Others"
}

# --- NEW: DURATION MAPPING (A9 to T9) ---
# Maps category + value -> Cell Address
DURATION_MAPPING = {
    "days":   {"1": "A9", "2": "B9", "3": "C9", "4": "D9", "5": "E9"},
    "weeks":  {"1": "F9", "2": "G9", "3": "H9", "4": "I9"},
    "months": {"2": "J9", "4": "K9", "6": "L9", "8": "M9", "10": "N9", "12": "O9"},
    "years":  {"1": "P9", "2": "Q9", "3": "R9", "4": "S9", "5": "T9"}
}

# -------------------------
# HELPER FUNCTIONS
# -------------------------
def get_next_job_no():
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
        return 1001
    
    existing_files = glob.glob(os.path.join(OUTPUT_FOLDER, "Job_*.pdf"))
    if not existing_files:
        return 1001
        
    try:
        nums = [int(os.path.basename(f).split("_")[-1].split(".")[0]) for f in existing_files]
        return max(nums) + 1
    except:
        return 1001

def write_labeled_cell(ws, addr, value):
    try:
        base = ws.Range(addr).Value
        base_str = "" if base is None else str(base)
        val_str = "" if value is None else str(value)

        if val_str.strip() == "":
            ws.Range(addr).Value = base_str.strip()
            return

        label = base_str
        if not label.endswith(" "):
            label += " "
        ws.Range(addr).Value = label + val_str
    except Exception as e:
        print(f"Error writing to {addr}: {e}")

# -------------------------
# ROUTES
# -------------------------
@app.route('/')
def index():
    return send_from_directory('web', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('web', path)

@app.route('/api/get-job-no', methods=['GET'])
def api_get_job_no():
    return jsonify({"job_no": get_next_job_no()})

@app.route('/api/generate', methods=['POST'])
def generate_report():
    data = request.json
    job_no = get_next_job_no()
    
    excel = None
    wb = None
    
    try:
        # Verify paths
        abs_template = os.path.abspath(TEMPLATE_FILE)
        if not os.path.exists(abs_template):
            return jsonify({"success": False, "error": "Template file not found."}), 500

        # Output paths
        new_filename = f"Job_{job_no}.xlsx"
        abs_save_path = os.path.abspath(os.path.join(OUTPUT_FOLDER, new_filename))
        abs_pdf_path = abs_save_path.replace(".xlsx", ".pdf")

        # Initialize Excel
        excel = win32.Dispatch("Excel.Application")
        excel.Visible = False
        excel.DisplayAlerts = False
        wb = excel.Workbooks.Open(abs_template)
        ws = wb.Worksheets(1)

        # 1. Write Job No
        ws.Range(JOB_NO_CELL).Value = job_no

        # 2. Write Labeled Fields
        write_labeled_cell(ws, LABELED_FIELDS["description"], data.get("description", ""))
        write_labeled_cell(ws, LABELED_FIELDS["objective"], data.get("objective", ""))
        write_labeled_cell(ws, LABELED_FIELDS["note"], data.get("note", ""))
        write_labeled_cell(ws, LABELED_FIELDS["remarks"], data.get("remarks", ""))

        # 3. Write Personnel
        ws.Range(CELL_MAP["engineer"]).Value = data.get("engineer", "")
        ws.Range(CELL_MAP["head_section"]).Value = data.get("head_section", "")

        # 4. Write Dates
        def fmt_date(d_str):
            if not d_str: return ""
            return datetime.strptime(d_str, "%Y-%m-%d").strftime("%d/%m/%Y")

        ws.Range(DATE_MAP["main_date"]).Value = fmt_date(data.get("main_date"))
        ws.Range(DATE_MAP["start_date"]).Value = fmt_date(data.get("start_date"))
        write_labeled_cell(ws, DATE_MAP["end_date"], fmt_date(data.get("end_date")))

        # 5. Handle Shapes (Type & Dept)
        try:
            for shape in list(TYPE_MAPPING.values()) + list(TO_SECTION_MAPPING.values()):
                try: ws.Shapes(shape).Fill.ForeColor.RGB = 16777215 # White
                except: pass
            
            work_type = TYPE_MAPPING.get(data.get("work_type", "Site"))
            dept = TO_SECTION_MAPPING.get(data.get("department"))
            
            if work_type: ws.Shapes(work_type).Fill.ForeColor.RGB = 0 # Black
            if dept: ws.Shapes(dept).Fill.ForeColor.RGB = 0 # Black
        except Exception as e:
            print(f"Shape error: {e}")

        # 6. HANDLE DURATION HIGHLIGHTING (A9-T9)
        # Reset range A9:T9 to transparent/white first if needed, or assume template is clean
        # Highlight selected cells
        
        # Define color (e.g., Light Yellow or custom). using standard Yellow here (65535) 
        # or similar to your previous logic.
        HIGHLIGHT_COLOR = 65535  # Yellow
        
        cats = ["days", "weeks", "months", "years"]
        for cat in cats:
            val = data.get(f"duration_{cat}") # e.g. "3"
            if val and val in DURATION_MAPPING[cat]:
                cell_addr = DURATION_MAPPING[cat][val]
                ws.Range(cell_addr).Interior.Color = HIGHLIGHT_COLOR

        # Save and Export
        wb.SaveAs(abs_save_path)
        ws.ExportAsFixedFormat(0, abs_pdf_path)
        
        wb.Close(SaveChanges=False)
        excel.Quit()

        try:
            os.startfile(abs_pdf_path)
        except:
            pass

        return jsonify({"success": True, "message": "Report generated successfully!", "file": abs_pdf_path})

    except Exception as e:
        if wb: wb.Close(SaveChanges=False)
        if excel: excel.Quit()
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    import webbrowser
    webbrowser.open("http://127.0.0.1:5000")
    app.run(debug=True, port=5000)