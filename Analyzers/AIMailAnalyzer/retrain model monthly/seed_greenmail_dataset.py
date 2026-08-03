"""
seed_greenmail_dataset.py — Outil de dev UNIQUEMENT, pas partie de la pipeline
de réentraînement elle-même. Peuple la boîte GreenMail locale
(deployment/docker-compose.override.yml) avec de faux mails "challenged"
réalistes, un par catégorie de la taxonomie (Re_Train_Model/variable.py),
pour pouvoir tester generator_dataset.py -> main_retrainmodels.py sans
attendre de vrais mails triés par des analystes.

Ce que ça simule :
  - Les 8 dossiers IMAP créés côté serveur (normalement fait une fois, à la
    main, par un admin messagerie - ici recréés à chaque run car GreenMail
    est en mémoire et perd tout au restart du conteneur)
  - Des mails "forwardés" (message/rfc822), comme le ferait un vrai analyste
    qui file un mail suspect revu vers le bon dossier - generator_dataset.py
    n'extrait QUE ce format (_extract_forwarded_body)
  - Un contenu différencié par sous-catégorie (pas de lorem ipsum générique)
  - Un déséquilibre de classes réaliste (beaucoup plus de safe/spam que de
    dangerous, et parmi le dangerous, classic >> whaling/blackmail) pour que
    le SMOTE/ROS de utils.py ait vraiment quelque chose à corriger
  - Un mélange FR/EN, cohérent avec le vectorizer multilingue

Usage :
  python seed_greenmail_dataset.py
  python seed_greenmail_dataset.py --flush   # vide les dossiers avant de re-seed
"""

import argparse
import email.utils
import imaplib
import os
import random
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart

from dotenv import load_dotenv

load_dotenv()

IMAP_HOST = os.environ.get("IMAP_HOST", "127.0.0.1")
IMAP_PORT = int(os.environ.get("IMAP_PORT", 3143))
IMAP_USER = os.environ.get("IMAP_USER", "suspicious@meridian.example")
IMAP_PASSWORD = os.environ.get("IMAP_PASSWORD", "meridian_dev_imap_pw")

# Analystes CERT fictifs "Meridian" (mêmes personas que docker-compose.override.yml)
ANALYSTS = ["elena.voss@meridian.example", "sam.whitfield@meridian.example"]

EMPLOYEES = [
    ("Jordan Kim", "jordan.kim@meridian.example"),
    ("Camila Reyes", "camila.reyes@meridian.example"),
    ("Haruto Sato", "haruto.sato@meridian.example"),
    ("Adaeze Okafor", "adaeze.okafor@meridian.example"),
]

EXECS = [("Elena Voss", "CISO"), ("Marcus Ferreira", "CFO"), ("Lian Zhou", "CEO")]

FAKE_DOMAINS = [
    "meridian-secure-portal.net", "meridian-hr-verify.com", "account-meridian.support",
    "meridian-billing-center.info", "secure-meridian-mail.online",
]

# ── Générateurs de contenu par catégorie ────────────────────────────────

def _legit_internal():
    emp1, addr1 = random.choice(EMPLOYEES)
    emp2, addr2 = random.choice(EMPLOYEES)
    subjects_bodies = [
        (f"Compte-rendu réunion équipe {random.choice(['Marketing', 'Finance', 'IT'])}",
         f"Bonjour,\n\nVoici le compte-rendu de notre réunion de ce matin. "
         f"Les actions sont assignées, merci de confirmer d'ici vendredi.\n\nCordialement,\n{emp1}"),
        ("IT Maintenance Window - This Weekend",
         f"Hi team,\n\nScheduled maintenance on internal systems this Saturday 22:00-02:00 CET. "
         f"No action needed on your end.\n\nBest,\n{emp1}"),
        (f"Note de service - Politique télétravail",
         f"Bonjour à tous,\n\nLa politique de télétravail est mise à jour à partir du mois prochain. "
         f"Détails en pièce jointe RH.\n\n{emp1}, RH"),
    ]
    subject, body = random.choice(subjects_bodies)
    return addr1, addr2, subject, body


def _legit_external():
    partner_domains = ["partner-corp.com", "supplier-group.eu", "client-services.io"]
    domain = random.choice(partner_domains)
    subjects_bodies = [
        ("Contract Renewal - Q3 Review",
         f"Dear Meridian team,\n\nAs discussed, please find attached the renewed service contract for review. "
         f"Let us know if you have questions.\n\nBest regards,\nPartner Corp Account Team"),
        ("Facture Fournisseur - Echéance 30 jours",
         f"Bonjour,\n\nVeuillez trouver ci-joint la facture n°{random.randint(10000,99999)} relative à notre "
         f"dernière commande. Paiement sous 30 jours.\n\nCordialement,\nService Comptabilité"),
    ]
    subject, body = random.choice(subjects_bodies)
    return f"contact@{domain}", "jordan.kim@meridian.example", subject, body


def _spam():
    # Body includes a random reward/discount amount and a claim code so each
    # generated mail hashes uniquely (calculate_hash() dedupes on body text -
    # a fully static template here would cap this label at a handful of rows
    # forever, no matter how many mails are seeded).
    subjects_bodies = [
        ("You've been selected! Claim your reward now",
         f"CONGRATULATIONS! You are one of our lucky winners. Click below to claim your "
         f"${random.choice([250, 500, 750, 1000])} gift card before it expires! Code: {random.randint(100000,999999)}"),
        ("Meilleurs prix sur les montres de luxe - -70%",
         f"Profitez de notre vente flash exceptionnelle (-{random.choice([50,60,70,80])}%), stock limité "
         f"({random.randint(3,20)} restants), livraison gratuite en France. Réf. promo {random.randint(1000,9999)}."),
        ("Perte de poids garantie en 2 semaines",
         f"Notre nouvelle formule révolutionnaire fait fureur. Commandez avant le "
         f"{random.randint(1,28)}/{random.randint(1,12)} et économisez {random.choice([30,40,50])}%."),
    ]
    subject, body = random.choice(subjects_bodies)
    return f"promo@{random.choice(['dealz-now.biz','superoffers.top'])}", "jordan.kim@meridian.example", subject, body


def _newsletter():
    # Same reasoning as _spam(): a random issue number/week makes each body
    # unique so the dataset can actually accumulate more than 1-2 rows.
    subjects_bodies = [
        (f"Your Weekly Tech Digest - Week {random.randint(1,52)}",
         f"This week in tech: new frameworks, security patches, and industry news "
         f"(issue #{random.randint(100,999)}). Unsubscribe anytime."),
        (f"Bulletin mensuel Cybersécurité - N°{random.randint(1,99)}",
         f"Ce mois-ci : les dernières vulnérabilités CVE ({random.randint(2020,2026)}-{random.randint(1000,90000)}), "
         f"tendances ransomware, et bonnes pratiques."),
    ]
    subject, body = random.choice(subjects_bodies)
    return "newsletter@security-weekly.com", "sam.whitfield@meridian.example", subject, body


def _classic_phishing():
    emp, addr = random.choice(EMPLOYEES)
    domain = random.choice(FAKE_DOMAINS)
    subjects_bodies = [
        ("Action Required: Your account will be suspended",
         f"Dear {emp},\n\nWe detected unusual activity on your account. To avoid suspension within 24h, "
         f"please verify your identity here: https://{domain}/verify?user={emp.split()[0].lower()}\n\nIT Security Team"),
        ("Votre mot de passe expire aujourd'hui",
         f"Bonjour {emp},\n\nVotre mot de passe Meridian expire dans quelques heures. Cliquez ici pour le renouveler "
         f"immédiatement : https://{domain}/reset\n\nSupport Informatique"),
    ]
    subject, body = random.choice(subjects_bodies)
    return f"security-noreply@{domain}", addr, subject, body


def _whaling_phishing():
    exec_name, exec_title = random.choice(EXECS)
    emp, addr = random.choice(EMPLOYEES)
    domain = random.choice(FAKE_DOMAINS)
    subjects_bodies = [
        (f"Urgent - Confidential wire transfer",
         f"Hi {emp.split()[0]},\n\nI need you to process an urgent, confidential wire transfer for a deal we're "
         f"closing today. Call is not possible right now, please handle by email only. Amount: €{random.randint(15,95)}k. "
         f"I'll send bank details shortly.\n\n{exec_name}\n{exec_title}, Meridian"),
        (f"Demande urgente et confidentielle",
         f"Bonjour {emp.split()[0]},\n\nJ'ai besoin de votre aide immédiatement pour un virement urgent lié à une "
         f"acquisition en cours, strictement confidentiel. Répondez uniquement par mail.\n\n{exec_name}"),
    ]
    subject, body = random.choice(subjects_bodies)
    spoofed_from = f"{exec_name.lower().replace(' ', '.')}@{domain}"
    return spoofed_from, addr, subject, body


def _clone_phishing():
    emp, addr = random.choice(EMPLOYEES)
    domain = random.choice(FAKE_DOMAINS)
    subjects_bodies = [
        ("Contract Renewal - Q3 Review",
         f"Dear Meridian team,\n\nAs discussed, please find the renewed contract for review here: "
         f"https://{domain}/contract-review-Q3.pdf\n\nBest regards,\nPartner Corp Account Team"),
        ("Facture Fournisseur - Echéance 30 jours",
         f"Bonjour,\n\nVeuillez consulter la facture mise à jour ici (lien sécurisé) : https://{domain}/facture.pdf\n\n"
         f"Cordialement,\nService Comptabilité"),
    ]
    subject, body = random.choice(subjects_bodies)
    return f"contact@{domain}", addr, subject, body


def _blackmailing_phishing():
    emp, addr = random.choice(EMPLOYEES)
    subjects_bodies = [
        ("I have access to your device",
         f"I know your password, it was {random.choice(['hunter2','password123','summer2025'])} at some point. "
         f"I installed malware on your device and recorded compromising footage. Pay 0.05 BTC to "
         f"{''.join(random.choices('abcdef0123456789', k=34))} within 48h or I send it to all your contacts."),
        ("J'ai accès à votre webcam",
         "Je surveille votre activité depuis plusieurs semaines. J'ai des preuves compromettantes. "
         "Payez l'équivalent en Bitcoin sous 48h sinon tout sera envoyé à vos contacts professionnels."),
    ]
    subject, body = random.choice(subjects_bodies)
    return "anon.actor@protonmail.onion.link", addr, subject, body


# folder -> (générateur, nombre de mails à créer) — déséquilibre volontairement
# réaliste : beaucoup de safe/spam, peu de dangerous, et parmi le dangerous,
# classic >> whaling/blackmail (comme une vraie boîte de review).
FOLDER_SPEC = {
    "0_LEGIT_INTERNAL_COMMUNICATION": (_legit_internal, 30),
    "0_LEGIT_EXTERNAL_COMMUNICATION": (_legit_external, 25),
    "1_SPAM": (_spam, 22),
    "1_NEWSLETTER": (_newsletter, 18),
    "2_CLASSIC_PHISHING": (_classic_phishing, 20),
    "2_WHALING_PHISHING": (_whaling_phishing, 9),
    "2_CLONE_PHISHING": (_clone_phishing, 12),
    "2_BLACKMAILING_PHISHING": (_blackmailing_phishing, 8),
}


def build_forwarded_mail(analyst: str, category: str, sender: str, to: str, subject: str, body: str) -> bytes:
    """Construit un mail 'challenged' réaliste : un forward de l'analyste
    contenant le mail suspect original en message/rfc822 - le seul format
    que generator_dataset.py::_extract_forwarded_body sait lire."""
    inner = EmailMessage()
    inner["From"] = sender
    inner["To"] = to
    inner["Subject"] = subject
    inner["Date"] = email.utils.formatdate(localtime=True)
    inner.set_content(body)

    outer = MIMEMultipart()
    outer["From"] = analyst
    outer["To"] = IMAP_USER
    outer["Subject"] = f"Fwd: {subject} [{category}]"
    outer["Date"] = email.utils.formatdate(localtime=True)
    from email.mime.text import MIMEText
    outer.attach(MIMEText(f"Mail suspect transféré pour classification manuelle ({category}).", "plain"))

    from email.mime.message import MIMEMessage
    outer.attach(MIMEMessage(inner))

    return outer.as_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flush", action="store_true", help="Vide les dossiers avant de re-seed")
    parser.add_argument("--seed", type=int, default=42, help="Graine aléatoire (reproductibilité)")
    args = parser.parse_args()
    random.seed(args.seed)

    conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
    conn.login(IMAP_USER, IMAP_PASSWORD)
    print(f"Connecté à {IMAP_HOST}:{IMAP_PORT} en tant que {IMAP_USER}")

    total = 0
    for folder, (generator, count) in FOLDER_SPEC.items():
        status, _ = conn.create(f'"{folder}"')
        print(f"  Dossier {folder!r}: {'créé' if status == 'OK' else 'déjà existant'}")

        if args.flush:
            conn.select(f'"{folder}"')
            status, data = conn.search(None, "ALL")
            if status == "OK" and data[0]:
                ids = b",".join(data[0].split())
                conn.store(ids, "+FLAGS", r"(\Deleted)")
                conn.expunge()
                print(f"    → vidé ({len(data[0].split())} mail(s) supprimé(s))")

        for _ in range(count):
            analyst = random.choice(ANALYSTS)
            sender, to, subject, body = generator()
            raw = build_forwarded_mail(analyst, folder, sender, to, subject, body)
            conn.append(f'"{folder}"', "", imaplib.Time2Internaldate(__import__("time").time()), raw)
            total += 1

        print(f"    → {count} mail(s) 'challenged' ajouté(s)")

    conn.logout()
    print(f"\n✅ {total} mails ajoutés au total sur {len(FOLDER_SPEC)} dossiers.")
    print("   Lancez maintenant: python generator_dataset.py")


if __name__ == "__main__":
    main()
