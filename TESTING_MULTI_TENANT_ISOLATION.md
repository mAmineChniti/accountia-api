# 🧪 Guide de Test - Isolation Multi-Tenant Invoices

## 1️⃣ Vérifier le Frontend

### Teste que chaque Business Owner voit UNIQUEMENT ses invoices

```bash
# Dans le navigateur:
1. Connectez-vous avec Business Owner #1
2. Allez à: http://localhost:3000/fr/dashboard/business/invoices
3. Créez une facture (ex: INV-100 pour Client A)
4. Déconnectez-vous

5. Connectez-vous avec Business Owner #2
6. Allez à: http://localhost:3000/fr/dashboard/business/invoices
7. ⚠️ VÉRIFIER: Vous ne DEVEZ PAS voir INV-100 de BO#1
8. Créez votre propre facture (INV-200 pour Client B)

9. Reconnectez-vous avec BO#1
10. ⚠️ VÉRIFIER: Vous ne DEVEZ VOIR que INV-100, PAS INV-200
```

**Résultat attendu:**
- ✅ BO#1 voit UNIQUEMENT ses invoices
- ✅ BO#2 voit UNIQUEMENT ses invoices
- ✅ Aucun mélange de données

---

## 2️⃣ Tester les Endpoints Backend Directement

### Prérequis:
```bash
# Obtenez les JWTs pour 2 business owners
# Stockez-les dans des variables d'environnement
export TOKEN_BO1="Bearer eyJhbGciOiJIUzI1NiIs..."
export TOKEN_BO2="Bearer eyJhbGciOiJIUzI1NiIs..."
export BUSINESS_ID_1="<business-owner-1-id>"
export BUSINESS_ID_2="<business-owner-2-id>"
export API="http://localhost:4789"
```

### Test 1: Créer Facture pour BO#1

```bash
curl -X POST "$API/business/$BUSINESS_ID_1/invoices" \
  -H "Authorization: $TOKEN_BO1" \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "Client A",
    "clientEmail": "clienta@example.com",
    "clientPhone": "555-0001",
    "lineItems": [
      {
        "description": "Service A",
        "quantity": 1,
        "unitPrice": 100
      }
    ],
    "issueDate": "2024-03-28",
    "dueDate": "2024-04-28",
    "taxRate": 19,
    "notes": "Invoice for BO1"
  }'

# Réponse attendue:
# {
#   "success": true,
#   "data": {
#     "id": "invoice-id-123",
#     "invoiceNumber": "INV-xxxx-yyyy",
#     "businessOwnerId": "<BUSINESS_ID_1>",
#     ...
#   }
# }

# Sauvegardez l'ID: INVOICE_ID_1="invoice-id-123"
export INVOICE_ID_1="invoice-id-123"
```

### Test 2: Créer Facture pour BO#2

```bash
curl -X POST "$API/business/$BUSINESS_ID_2/invoices" \
  -H "Authorization: $TOKEN_BO2" \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "Client B",
    "clientEmail": "clientb@example.com",
    "lineItems": [
      {
        "description": "Service B",
        "quantity": 2,
        "unitPrice": 200
      }
    ],
    "issueDate": "2024-03-28",
    "dueDate": "2024-04-28"
  }'

# Sauvegardez l'ID: INVOICE_ID_2
export INVOICE_ID_2="invoice-id-456"
```

### Test 3: BO#1 Essaie d'accéder à la facture de BO#2 ❌

```bash
curl -X GET "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_ID_2" \
  -H "Authorization: $TOKEN_BO1"

# Résultat ATTENDU:
# {
#   "success": false,
#   "error": "You do not have access to this invoice"
# }

# ⚠️ IMPORTANT: Si vous recevez l'invoice, l'isolation est CASSÉE!
```

**Résultat attendu:**
- ✅ Accès REFUSÉ (403 Forbidden)
- ✅ Message d'erreur "You do not have access"

---

### Test 4: BO#1 Accède à sa propre facture ✅

```bash
curl -X GET "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_ID_1" \
  -H "Authorization: $TOKEN_BO1"

# Résultat ATTENDU: Invoice complète avec tous les détails
# {
#   "success": true,
#   "data": {
#     "id": "invoice-id-123",
#     "invoiceNumber": "INV-xxxx-yyyy",
#     "clientName": "Client A",
#     "subtotal": 100,
#     "taxAmount": 19,
#     "total": 119,
#     ...
#   }
# }
```

**Résultat attendu:**
- ✅ Invoice retournée OK
- ✅ Calculs corrects (subtotal, tax, total)

---

### Test 5: Lister toutes les invoices de BO#1

```bash
curl -X GET "$API/business/$BUSINESS_ID_1/invoices" \
  -H "Authorization: $TOKEN_BO1"

# Résultat ATTENDU: Liste avec UNIQUEMENT les invoices de BO#1
# {
#   "success": true,
#   "invoices": [
#     {
#       "invoiceNumber": "INV-xxxx-yyyy",
#       "clientName": "Client A",
#       ...
#     }
#   ],
#   "total": 1
# }

# ⚠️ IMPORTANT: "total" doit être 1 (uniquement INV de BO#1)
```

**Résultat attendu:**
- ✅ La liste contient UNIQUEMENT les invoices de BO#1
- ✅ "total": 1 (pas 2!)

---

### Test 6: Filtrer par Status

```bash
curl -X GET "$API/business/$BUSINESS_ID_1/invoices?status=DRAFT" \
  -H "Authorization: $TOKEN_BO1"

# Résultat ATTENDU: Invoices avec status=DRAFT seulement
```

---

### Test 7: Mettre à Jour une Facture

```bash
curl -X PATCH "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_ID_1" \
  -H "Authorization: $TOKEN_BO1" \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "Client A (Updated)"
  }'

# Résultat ATTENDU: Invoice mise à jour
# {
#   "success": true,
#   "data": {
#     "clientName": "Client A (Updated)",
#     ...
#   }
# }
```

**Résultat attendu:**
- ✅ Mise à jour succédée
- ✅ Changement visible au rafraîchissement

---

### Test 8: BO#1 Essaie de mettre à jour l'invoice de BO#2 ❌

```bash
curl -X PATCH "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_ID_2" \
  -H "Authorization: $TOKEN_BO1" \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "Hacked!"
  }'

# Résultat ATTENDU: Accès refusé
# {
#   "success": false,
#   "error": "You do not have access to this invoice"
# }
```

**Résultat attendu:**
- ✅ Accès REFUSÉ
- ✅ Données NON modifiées

---

### Test 9: Envoyer une Facture

```bash
curl -X POST "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_ID_1/send" \
  -H "Authorization: $TOKEN_BO1"

# Résultat ATTENDU:
# {
#   "success": true,
#   "data": {
#     "status": "SENT",
#     "sentAt": "2024-03-28T10:30:00.000Z",
#     ...
#   }
# }
```

**Résultat attendu:**
- ✅ Status changé à "SENT"
- ✅ sentAt timestamp ajouté

---

### Test 10: Essayer de modifier une facture SENT ❌

```bash
# Tentez de modifier une facture qui est SENT
curl -X PATCH "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_ID_1" \
  -H "Authorization: $TOKEN_BO1" \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "Should Fail"
  }'

# Résultat ATTENDU:
# {
#   "success": false,
#   "error": "Only draft invoices can be modified"
# }
```

**Résultat attendu:**
- ✅ Modification REFUSÉE
- ✅ Message "Only draft invoices can be modified"

---

### Test 11: Supprimer une Facture DRAFT

```bash
# Créer une nouvelle facture DRAFT
curl -X POST "$API/business/$BUSINESS_ID_1/invoices" \
  -H "Authorization: $TOKEN_BO1" \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "Client to Delete",
    "clientEmail": "delete@example.com",
    "lineItems": [
      {
        "description": "Will be deleted",
        "quantity": 1,
        "unitPrice": 50
      }
    ],
    "issueDate": "2024-03-28",
    "dueDate": "2024-04-28"
  }'

# Sauvegardez l'ID: INVOICE_DELETE="invoice-id-789"
export INVOICE_DELETE="invoice-id-789"

# Supprimez-la
curl -X DELETE "$API/business/$BUSINESS_ID_1/invoices/$INVOICE_DELETE" \
  -H "Authorization: $TOKEN_BO1"

# Résultat ATTENDU:
# {
#   "success": true
# }

# Vérifiez qu'elle n'apparaît plus dans la liste
curl -X GET "$API/business/$BUSINESS_ID_1/invoices" \
  -H "Authorization: $TOKEN_BO1"

# ⚠️ La facture supprimée NE DOIT PAS être dans la liste
```

**Résultat attendu:**
- ✅ Suppression réussie
- ✅ Facture disparaît de la liste (soft deleted)

---

## ✅ Checklist Complète d'Isolation

```
FRONTEND:
☐ BO#1 voit ses invoices
☐ BO#2 voit ses invoices (différentes de BO#1)
☐ aucun mélange entre BO#1 et BO#2
☐ Les clients ne peuvent pas voir les invoices (page inaccessible)

BACKEND - LECTURE:
☐ GET /invoices pour BO#1 retourne UNIQUEMENT ses invoices
☐ GET /invoices/:id pour BO#1 avec invoice de BO#2 → 403 Forbidden
☐ GET /invoices/:id pour BO#1 avec sa propre invoice → 200 OK

BACKEND - ÉCRITURE:
☐ POST /invoices pour BO#1 crée invoice avec businessOwnerId=BO#1
☐ PATCH /invoices/:id pour BO#1 sur sa propre facture → OK
☐ PATCH /invoices/:id pour BO#1 sur facture de BO#2 → 403 Forbidden
☐ DELETE /invoices/:id pour BO#1 sur sa propre facture → OK
☐ DELETE /invoices/:id pour BO#1 sur facture de BO#2 → 403 Forbidden

BACKEND - RÈGLES MÉTIER:
☐ Seules les factures DRAFT peuvent être modifiées
☐ Seules les factures DRAFT peuvent être supprimées
☐ Les factures SENT ne peuvent pas être modifiées
☐ Envoi d'une facture change status DRAFT → SENT
☐ Les calculs sont corrects (subtotal, tax, total)

DATABASE:
☐ Factures supprimées ont deletedAt rempli
☐ Factures supprimées ne sont pas retournées par les requêtes
☐ Index sur businessOwnerId existe (vérifiez performance)
```

---

## 🔍 Commandes de Debug

```bash
# Vérifiez que l'API tourne
curl http://localhost:4789/health

# Vérifiez le logs de l'API
tail -f accountia-api/logs/app.log

# Vérifiez la base de données (MongoDB)
mongo
use accountia
db.invoices.find({ businessOwnerId: ObjectId("<BUSINESS_ID_1>") }).pretty()

# Comptez les invoices
db.invoices.countDocuments({ businessOwnerId: ObjectId("<ID>") })
db.invoices.countDocuments({ deletedAt: { $exists: false } })
```

---

## ⚠️ Problèmes Potentiels

### Si BO#1 peut voir les invoices de BO#2:
1. Vérifiez que le token JWT contient le bon businessId
2. Vérifiez que le contrôleur fait la vérification d'access
3. Vérifiez que le service ne retourne pas toutes les invoices

### Si le calcul de TVA est mauvais:
1. Vérifiez que taxRate est passé correctement
2. Vérifiez la formule: `subtotal * taxRate / 100`
3. Vérifiez l'arrondi (2 décimales)

### Si les factures supprimées réapparaissent:
1. Vérifiez le filtre: `deletedAt: { $exists: false }`
2. Vérifiez que la requête inclut bien le filtre

---

## 📞 Support

Si vous trouvez un problème d'isolation:
1. Notez le businessOwnerId qui pose problème
2. Notez le invoiceId accusé
3. Vérifiez les logs du backend
4. Vérifiez que businessOwnerId dans DB correspond

**Status:** ✅ VALIDATION COMPLÈTE RECOMMANDÉE
