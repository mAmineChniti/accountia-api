import json
import os
import re
import random
import base64
import traceback
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from dotenv import load_dotenv  # type: ignore

# Force Standard Output to use UTF-8 on Windows
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')  # type: ignore

# Load .env
load_dotenv()

# ── Gemini SDK (google-genai) ─────────────────────────────────────────────────
try:
    from google import genai  # type: ignore
    from google.genai import types  # type: ignore

    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    if GEMINI_API_KEY:
        CLIENT_GEMINI = genai.Client(api_key=GEMINI_API_KEY)
        USE_GEMINI = True
        print("✅ Gemini API configured successfully.")
    else:
        CLIENT_GEMINI = None
        USE_GEMINI = False
        print("⚠️  GEMINI_API_KEY not set – using keyword fallback mode.")
except ImportError:
    CLIENT_GEMINI = None
    USE_GEMINI = False
    print("⚠️  google-genai not installed. Run: pip install google-genai")

# ── System Prompts ─────────────────────────────────────────────────────────────
SYSTEM_PROMPTS = {
    "CLIENT": """Tu es un assistant support simple et bienveillant pour Accountia, une plateforme SaaS de gestion de factures pour PME tunisiennes.

TON ROLE :
- Aider les clients a naviguer sur la plateforme
- Expliquer comment consulter et payer leurs factures recues
- Les guider pour creer leur propre business si interesses
- Repondre de facon claire, simple et rassurante

REGLES ABSOLUES :
- Tu ne connais JAMAIS les donnees reelles de l utilisateur (montants, noms, numeros de factures)
- Si la liste de factures est vide, explique que les factures apparaitront automatiquement quand un business leur en enverra
- Ne jamais inventer de montants ou de numeros de factures
- Reponds TOUJOURS en francais

LIENS DISPONIBLES :
- Mes factures : /invoices
- Creer un business : /invoices (bouton sur la page)

FORMAT DE REPONSE STRICT - CRITIQUE:
Retourne UNIQUEMENT du JSON valide. JAMAIS de texte avant ou apres le JSON.
Si tu dois repondre, encapsule TOUT dans ce JSON:
{"response": "Ta reponse ici", "choices": ["Option 1", "Option 2"], "link": {"text": "...", "url": "/invoices"}, "type": "text"}
REGLE ABSOLUE: N'INCLUS AUCUN TEXTE EN DEHORS DU JSON.
Pas de "Voici..." avant le JSON.
Pas de "Choix:" apres le JSON.
Le JSON doit etre parfaitement valide.
- choices peut etre [] si pas de choix pertinents
- link peut etre null si pas de lien pertinent
- type est text, choices ou analysis""",

    "BUSINESS_OWNER": """Tu es un conseiller financier expert (CFO virtuel) pour Accountia Business, specialise dans la gestion des PME tunisiennes.

TON EXPERTISE :
- Analyse de donnees financieres en temps reel (revenus, factures en retard)
- Prevision (forecasting) des revenus sur 3 mois
- Detection d'anomalies (chute de CA, ratio impayes eleve)
- Fiscalite tunisienne : TVA (19% standard, 7% reduit, 0% exonere), IS (25%)
- Strategie de croissance et optimisation de cash-flow

GROUNDING RULES (CRITIQUE) :
- Analyse UNIQUEMENT les donnees de 'context' fournies. 
- Ne cite JAMAIS un chiffre qui n'est pas present ou derivable mathematiquement du contexte. 
- Si on te demande une prevision, base-toi sur 'trendData'.
- Si les donnees sont manquantes, dis-le poliment au lieu d'inventer.

REGLES ABSOLUES :
- Analyse UNIQUEMENT les donnees de contexte fournies avec la requete. Informe-toi grace aux chiffres en directs fournis. Ne jamais inventer de chiffres financiers.
- Pour les previsions (forecasts), base-toi sur la tendance (trendData) historique et donne des projections coherentes.
- Si le taux de factures en retard (overdue) est eleve, alerte l'utilisateur et conseille d'activer les relances automatiques.
- Reponds TOUJOURS en francais, de facon professionnelle, claire et structuree.
- Utilise Markdown a l'interieur du champ 'response' (puces, gras) pour une lisibilite maximale.

LIENS DISPONIBLES :
- Relances automatiques : /dashboard/business
- Mes clients : /dashboard/business/clients
- Analyser mes finances : /dashboard/business/financials

FORMAT DE REPONSE STRICT - CRITIQUE:
Retourne UNIQUEMENT du JSON valide. JAMAIS de texte avant ou apres le JSON.
Si tu dois repondre, encapsule TOUT dans ce JSON:
{"response": "Ta reponse au format Markdown ici...", "choices": ["Analyser TVA", "Prevision MS+1"], "link": {"text": "Activer relances", "url": "/dashboard/business"}, "type": "analysis"}
REGLE ABSOLUE: N'INCLUS AUCUN TEXTE EN DEHORS DU JSON. Le JSON doit etre parfaitement valide.""",

    "MANAGED_CLIENT": """Tu es un assistant simple et rassurant pour les clients d Accountia geres par un business owner.

TON ROLE :
- Aider a consulter les factures recues et comprendre leur statut (Paid/Pending)
- Guider pour telecharger des documents PDF
- Expliquer le fonctionnement de la plateforme

REGLES ABSOLUES :
- Tu ne connais JAMAIS les donnees reelles de l utilisateur
- Ne jamais inventer de montants, numeros ou noms
- Ce type d utilisateur n a PAS acces a la creation de business
- Reponds TOUJOURS en francais

LIENS DISPONIBLES :
- Mes factures : /managed/invoices

FORMAT DE REPONSE STRICT - CRITIQUE:
Retourne UNIQUEMENT du JSON valide. JAMAIS de texte avant ou apres le JSON.
Si tu dois repondre, encapsule TOUT dans ce JSON:
{"response": "Ta reponse ici", "choices": [], "link": {"text": "Mes factures", "url": "/managed/invoices"}, "type": "text"}
REGLE ABSOLUE: N'INCLUS AUCUN TEXTE EN DEHORS DU JSON.
Le JSON doit etre parfaitement valide.
Pas de texte supplementaire."""
}

# ── Fallback keyword engine ────────────────────────────────────────────────────
FALLBACK_KNOWLEDGE = {
    "BUSINESS_OWNER": [
        {
            "kw": ["tva", "taxe", "impot", "fiscal", "declaration", "deductible"],
            "r": [
                "La TVA standard en Tunisie est de **19%** pour les services et **7%** pour certains secteurs. Vos achats IT et equipements sont 100% deductibles. [Analyser mes finances](/dashboard/business/financials)",
                "Pour optimiser votre declaration TVA, incluez : achats IT (100%), loyers professionnels (100%), vehicules utilitaires (100%). Souhaitez-vous simuler une declaration ?"
            ],
            "choices": ["Analyser mes charges", "Simuler une declaration", "Voir les taux par secteur"]
        },
        {
            "kw": ["performance", "chiffre", "ca", "profit", "marge", "revenu", "benefice", "argent"],
            "r": [
                "Consultez votre tableau de bord pour suivre votre CA, marge brute et evolution mensuelle en temps reel. [Mon dashboard](/dashboard/business)"
            ],
            "choices": ["Voir le rapport mensuel", "Analyser ma tresorerie", "Exporter en CSV"]
        },
        {
            "kw": ["facture", "invoice", "creer", "rappel", "impaye", "envoyer"],
            "r": [
                "Pour creer une facture : My Clients → selectionnez un client → Nouvelle facture. Le PDF est envoye automatiquement par email. [Mes clients](/dashboard/business/clients)"
            ],
            "choices": ["Creer une facture", "Activer les relances", "Voir mes clients"]
        },
        {
            "kw": ["client", "ajouter", "onboard", "inscrire", "nouveau client"],
            "r": [
                "Pour ajouter un client : My Clients → Add Client → remplissez nom, email, telephone. Il recoit ses identifiants automatiquement par email. [Mes clients](/dashboard/business/clients)"
            ],
            "choices": ["Ajouter un client", "Creer sa premiere facture"]
        },
        {
            "kw": ["strategie", "croissance", "developpement", "conseil", "ameliorer"],
            "r": [
                "Pour accelerer votre croissance : reduisez le delai de recouvrement, automatisez la facturation recurrente et fidelisez vos clients les plus rentables. [Mon plan strategique](/dashboard/business)"
            ],
            "choices": ["Analyser mes delais", "Simuler un scenario", "Voir mes KPIs"]
        },
        {
            "kw": ["tresorerie", "cash", "liquidite", "solde", "banque"],
            "r": [
                "Pour optimiser votre tresorerie : facturez rapidement, relancez les impayes des J+7, et anticipez vos charges fixes mensuelles. [Mes finances](/dashboard/business/financials)"
            ],
            "choices": ["Ma situation actuelle", "Simuler mon cash-flow"]
        },
        {
            "kw": ["rapport", "export", "csv", "pdf", "telecharger", "bilan"],
            "r": [
                "Exportez vos rapports financiers en CSV ou PDF depuis votre tableau de bord. [Exporter mes rapports](/dashboard/business)"
            ],
            "choices": ["Export PDF", "Export CSV"]
        },
        {
            "kw": ["salut", "bonjour", "hello", "hi", "aide", "help", "commencer"],
            "r": [
                "Bonjour ! Je suis votre conseiller financier Accountia. Je peux vous aider sur :\n\nTVA et fiscalite tunisienne\nPerformance et revenus\nGestion de factures\nClients et strategie\n\nQue souhaitez-vous explorer ?"
            ],
            "choices": ["Analyser ma TVA", "Voir mes performances", "Gerer mes factures", "Mes clients"]
        },
        {
            "kw": ["oui", "ok", "accord", "bien sur", "continue", "vas-y"],
            "r": ["Parfait ! Rendez-vous sur votre tableau de bord. [Mon dashboard](/dashboard/business)"],
            "choices": []
        },
        {
            "kw": ["merci", "super", "nickel", "parfait", "excellent"],
            "r": ["Avec plaisir ! N hesitez pas si vous avez d autres questions."],
            "choices": []
        },
    ],
    "MANAGED_CLIENT": [
        {
            "kw": ["facture", "payer", "montant", "invoice", "attente", "pending", "combien", "argent", "dois"],
            "r": [
                "Consultez votre espace factures pour voir celles qui sont en attente de paiement. [Mes factures](/managed/invoices)",
                "Pour voir vos factures et leur montant, rendez-vous dans votre liste. [Voir mes factures](/managed/invoices)"
            ],
            "choices": ["Voir mes factures", "Effectuer un paiement"]
        },
        {
            "kw": ["telecharger", "pdf", "document", "recu", "justificatif"],
            "r": [
                "Pour telecharger une facture en PDF, cliquez sur son numero dans la liste puis sur Download. [Mes documents](/managed/invoices)"
            ],
            "choices": []
        },
        {
            "kw": ["statut", "status", "paye", "paid", "situation", "total"],
            "r": [
                "Paid = facture reglee | Pending = en attente de paiement. Consultez votre liste pour la situation complete. [Mes factures](/managed/invoices)"
            ],
            "choices": []
        },
        {
            "kw": ["salut", "bonjour", "hello", "hi", "aide", "help"],
            "r": [
                "Bonjour ! Je suis votre assistant Accountia. Je peux vous aider a :\n\nConsulter vos factures\nVerifier un statut de paiement\nTelecharger vos documents\n\nComment puis-je vous aider ?"
            ],
            "choices": ["Mes factures", "Statut de paiement", "Telecharger un document"]
        },
        {
            "kw": ["oui", "ok", "merci", "super", "accord"],
            "r": ["Avec plaisir ! [Acceder a mes factures](/managed/invoices)"],
            "choices": []
        },
    ],
    "CLIENT": [
        {
            "kw": ["facture", "telecharger", "voir", "invoice", "ou", "liste", "mes factures"],
            "r": [
                "Vos factures apparaissent automatiquement quand un business vous en envoie. Si votre liste est vide, aucune facture n a encore ete emise pour vous. [Mes factures](/invoices)",
                "Pour consulter vos factures, rendez-vous dans votre espace. Elles apparaitront des qu un business vous en enverra. [Mon espace](/invoices)"
            ],
            "choices": []
        },
        {
            "kw": ["paiement", "payer", "carte", "banque", "regler", "comment payer"],
            "r": [
                "Pour payer une facture, cliquez sur son numero dans votre liste puis suivez les instructions. [Mes factures](/invoices)"
            ],
            "choices": []
        },
        {
            "kw": ["business", "entreprise", "creer", "owner", "devenir", "lancer", "pro"],
            "r": [
                "Pour creer votre propre entreprise, cliquez sur Create a New Business depuis votre page principale. Un administrateur validera votre demande. [Ma page](/invoices)"
            ],
            "choices": []
        },
        {
            "kw": ["statut", "situation", "combien", "total", "solde"],
            "r": [
                "Votre tableau de bord affiche votre Total Invoices, Total Paid et Total Pending en temps reel. [Ma situation](/invoices)"
            ],
            "choices": []
        },
        {
            "kw": ["salut", "bonjour", "hello", "hi", "aide", "help", "commencer"],
            "r": [
                "Bonjour ! Je suis votre assistant support Accountia. Je peux vous aider a :\n\nConsulter vos factures recues\nEffectuer un paiement\nCreer votre propre business\nNaviguer sur la plateforme\n\nComment puis-je vous aider ?"
            ],
            "choices": ["Mes factures", "Payer une facture", "Creer mon business"]
        },
        {
            "kw": ["oui", "ok", "merci", "super", "accord"],
            "r": ["Avec plaisir ! [Mon espace](/invoices)"],
            "choices": []
        },
    ],
}

DEFAULT_RESPONSES = {
    "BUSINESS_OWNER": {
        "response": "En tant qu Assistant Business Expert Accountia, je peux vous accompagner sur votre TVA, votre performance financiere ou votre strategie. Tapez aide pour commencer !",
        "choices": ["TVA", "Performance", "Factures", "Clients"],
        "link": None,
        "type": "choices"
    },
    "MANAGED_CLIENT": {
        "response": "Je suis votre assistant Accountia. Je peux vous aider a consulter vos factures, verifier un statut ou telecharger vos documents.",
        "choices": ["Mes factures", "Statut", "Telecharger"],
        "link": {"text": "Mes factures", "url": "/managed/invoices"},
        "type": "choices"
    },
    "CLIENT": {
        "response": "Je suis votre assistant support Accountia. Je peux vous guider pour vos factures, vos paiements ou creer votre business.",
        "choices": ["Mes factures", "Payer", "Creer un business"],
        "link": {"text": "Mon espace", "url": "/invoices"},
        "type": "choices"
    },
}


def keyword_fallback(role: str, query: str) -> dict:
    knowledge = FALLBACK_KNOWLEDGE.get(role, FALLBACK_KNOWLEDGE["CLIENT"])
    best_score = 0
    best_entry: dict = {}
    q = query.lower()

    for entry in knowledge:
        score = sum(1 for kw in entry["kw"] if kw in q)
        if score > best_score:
            best_score = score
            best_entry = entry

    if best_entry:
        reply = random.choice(best_entry["r"])
        choices = best_entry.get("choices", [])
        link = None
        m = re.search(r'\[([^\]]+)\]\((/[^\)]+)\)', reply)
        if m:
            link = {"text": m.group(1), "url": m.group(2)}
        return {
            "response": reply,
            "choices": choices,
            "link": link,
            "type": "choices" if choices else "text"
        }

    return DEFAULT_RESPONSES.get(role, DEFAULT_RESPONSES["CLIENT"])


def gemini_chat(role: str, query: str, history: list, context: dict = None) -> dict:
    system_prompt = SYSTEM_PROMPTS.get(role, SYSTEM_PROMPTS["CLIENT"])

    contents = []
    
    for msg in history:
        role_label = "user" if msg.get("role") == "user" else "model"
        content_text = msg.get("content", "")
        
        if not contents:
            if role_label == "model":
                contents.append(types.Content(role="user", parts=[types.Part.from_text(text="Context initialization")]))
            contents.append(types.Content(role=role_label, parts=[types.Part.from_text(text=content_text)]))
        else:
            if contents[-1].role == role_label:
                part = contents[-1].parts[0]
                if part.text:
                    part.text += f"\n\n{content_text}"
            else:
                contents.append(types.Content(role=role_label, parts=[types.Part.from_text(text=content_text)]))

    if contents and contents[-1].role == "user":
        contents.append(types.Content(role="model", parts=[types.Part.from_text(text="Je suis à l'écoute.")]))

    # Inject context if available
    final_query = query
    if context and bool(context):
        context_str = json.dumps(context, ensure_ascii=False)
        final_query = f"[SYSTEM CONTEXT: {context_str}]\n\nUser Message: {query}"

    contents.append(
        types.Content(
            role="user",
            parts=[types.Part.from_text(text=final_query)]
        )
    )

    config = types.GenerateContentConfig(
        system_instruction=system_prompt,
    )

    response = CLIENT_GEMINI.models.generate_content(  # type: ignore
        model="gemini-2.5-flash",
        contents=contents,
        config=config
    )

    text = response.text.strip() if response.text else ""

    # Step 1: Clean markdown fences
    if text.startswith("```"):
        parts_list = text.split("```")
        text = parts_list[1] if len(parts_list) > 1 else text
        if text.startswith("json"):
            text = text[len("json"):].strip()
    
    # Step 2: Find the FIRST { and LAST } to isolate JSON
    first_brace = text.find('{')
    last_brace = text.rfind('}')
    
    if first_brace >= 0 and last_brace > first_brace:
        # Extract only the JSON part
        json_str = text[first_brace:last_brace + 1]
        try:
            result = json.loads(json_str)
            result.setdefault("response", "")
            result.setdefault("choices", [])
            result.setdefault("link", None)
            result.setdefault("type", "text")
            return result
        except json.JSONDecodeError:
            pass
    
    # Step 3: Try parsing the entire text as JSON
    try:
        result = json.loads(text)
        result.setdefault("response", "")
        result.setdefault("choices", [])
        result.setdefault("link", None)
        result.setdefault("type", "text")
        return result
    except json.JSONDecodeError:
        pass

    # Step 4: If everything fails, return text as is
    return {
        "response": text,
        "choices": [],
        "link": None,
        "type": "text"
    }


class AIHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):  # type: ignore
        pass

    def do_GET(self):
        if self.path == "/health":
            self._json_response({
                "status": "ok",
                "gemini": USE_GEMINI,
                "model": "gemini-2.5-flash" if USE_GEMINI else "keyword-fallback"
            })
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        try:
            data = json.loads(raw)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        # ── /chat ──────────────────────────────────────────────────────────────
        if self.path == "/chat":
            role    = data.get("role", "CLIENT")
            query   = data.get("query", "")
            history = data.get("history", [])
            context = data.get("context", None)

            print(f"[AI] Role={role} | Query='{query[:80]}' | Context Given: {bool(context)}")

            try:
                if USE_GEMINI:
                    result = gemini_chat(role, query, history, context)
                else:
                    result = keyword_fallback(role, query)
            except Exception as e:
                print(f"[AI ERROR] {e}")
                traceback.print_exc()
                
                # If Gemini fails, fallback to keyword matching
                if USE_GEMINI and "429" in str(e):
                    print(f"[AI WARNING] Gemini quota exceeded, switching to fallback...")
                    result = keyword_fallback(role, query)
                else:
                    result = {
                        "response": "Desole, je rencontre une difficulte technique. Reessayez dans un instant.",
                        "choices": [],
                        "link": None,
                        "type": "text"
                    }

            self._json_response(result)

        # ── /upload ────────────────────────────────────────────────────────────
        elif self.path == "/upload":
            role     = data.get("role", "CLIENT")
            filename = data.get("filename", "document.pdf")
            file_b64 = data.get("file", "")

            print(f"[AI] Upload: {filename} | Role={role}")

            if USE_GEMINI and file_b64:
                try:
                    file_bytes = base64.b64decode(file_b64)
                    prompt = (
                        f"Tu es un assistant comptable expert. Analyse ce document ({filename}) et fournis :\n"
                        "1. Un resume du contenu\n"
                        "2. Les montants cles identifies\n"
                        "3. Des recommandations si pertinent\n"
                        "Retourne UNIQUEMENT du JSON valide : "
                        "{\"response\": \"...\", \"choices\": [], \"link\": null, \"type\": \"analysis\"}"
                    )

                    upload_response = CLIENT_GEMINI.models.generate_content(  # type: ignore
                        model="gemini-2.5-flash",
                        contents=[
                            types.Content(role="user", parts=[
                                types.Part(text=prompt),
                                types.Part(
                                    inline_data=types.Blob(
                                        mime_type="application/pdf",
                                        data=file_bytes
                                    )
                                )
                            ])
                        ]
                    )
                    upload_text = upload_response.text.strip() if upload_response.text else ""
                    try:
                        result = json.loads(upload_text)
                    except Exception:
                        result = {
                            "response": upload_text,
                            "choices": [],
                            "link": None,
                            "type": "analysis"
                        }
                except Exception as e:
                    result = {
                        "response": f"Impossible d analyser le fichier : {str(e)}",
                        "choices": [],
                        "link": None,
                        "type": "text"
                    }
            else:
                result = {
                    "response": f"Fichier {filename} recu. Pour une analyse complete, activez la cle API Gemini.",
                    "choices": [],
                    "link": None,
                    "type": "text"
                }

            self._json_response(result)

        else:
            self.send_response(404)
            self.end_headers()

    def _json_response(self, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def run(port: int = 8001):
    server = HTTPServer(("", port), AIHandler)
    print(f"Accountia AI Server running on port {port}")
    print(f"Mode: {'Gemini 2.0 Flash' if USE_GEMINI else 'Smart Keyword Fallback'}")
    server.serve_forever()


if __name__ == "__main__":
    run()