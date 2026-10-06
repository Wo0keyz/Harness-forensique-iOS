"""Cas iLEAPP synthétique : mêmes noms de fichiers et en-têtes qu'une vraie sortie iLEAPP,
contenu entièrement fictif et sans aucun incident. Sert de jeu d'essai aux tests et de cas
témoin à l'évaluation (un rapport qui y trouve une infraction l'a inventée).

Variante `ambiguous` : le même téléphone, avec des éléments qui ressemblent à des signaux mais
s'expliquent innocemment (menace en plaisantant, remboursement, message effacé, document de
travail envoyé à sa propre adresse, réinitialisation à la mise en service, jeu supprimé). Un
graphe qui cherche l'infraction ne doit y retenir aucun scénario."""

import csv
import json
from pathlib import Path

# nom de l'artefact -> (chemin source iOS déclaré par iLEAPP, en-têtes, lignes)
ARTIFACTS: dict[str, tuple[str, list[str], list[list[str]]]] = {
    "Device Data": (
        "private\\var\\containers\\Shared\\SystemGroup\\X\\Library\\Caches\\com.apple.MobileGestalt.plist",
        ["Property", "Property Value"],
        [
            ["Device Name", "iPhone de Camille"],
            ["Product Type", "iPhone14,8"],
            ["Product Version", "18.0"],
            ["Serial Number", "SYNTH0SERIAL"],
        ],
    ),
    "Account Data": (
        "private\\var\\mobile\\Library\\Accounts\\Accounts3.sqlite",
        ["Timestamp", "Account Desc.", "Username", "Description", "Identifier", "Bundle ID"],
        [["2030-01-02 08:00:00", "iCloud", "camille.test@example.org", "iCloud", "ID-1", "com.apple.icloud"]],
    ),
    "Testapp - Accounts": (
        "See Table for Source DB",
        ["Account ID", "Nickname"],
        [["ACC-42", "camille_t"]],
    ),
    "Keyboard Usage Stats": (  # aucun agent ne lit cet artefact : il doit apparaître comme « non lu »
        "private\\var\\mobile\\Library\\Keyboard\\stats.db",
        ["Date", "Words Typed"],
        [["2030-01-04", "120"], ["2030-01-05", "80"]],
    ),
    "Apps - Installed": (
        "private\\var\\mobile\\Library\\FrontBoard\\applicationState.db",
        ["Last Installed", "Bundle ID"],
        [
            ["2030-01-01 10:00:00", "org.whispersystems.signal"],
            ["2030-01-01 10:05:00", "com.example.notes"],
            ["2030-01-01 10:06:00", "com.apple.mobilesafari"],
        ],
    ),
    "SMS": (
        "private\\var\\mobile\\Library\\SMS\\sms.db",
        [
            "Message Timestamp",
            "From Me",
            "Chat Contact ID",
            "Message",
            "Service",
            "Message Direction",
            "Message Row ID",
        ],
        [
            [
                "2030-01-03 09:00:00",
                "0",
                "+33600000001",
                "Bonjour, le colis est arrivé",
                "SMS",
                "Incoming",
                "11",
            ],
            ["2030-01-03 09:05:00", "1", "+33600000001", "Merci, je passe demain", "SMS", "Outgoing", "12"],
        ],
    ),
    "Signal - Messages": (
        "See Table for Source DB",
        ["Timestamp", "Direction", "Author", "Conversation With", "Message", "Row ID"],
        [
            [
                "2030-01-04 18:00:00",
                "Incoming",
                "Paul Martin",
                "Paul Martin",
                "rendez-vous au quai 7 à 19h",
                "201",
            ],
            [
                "2030-01-04 18:02:00",
                "Outgoing",
                "",
                "Paul Martin",
                "d'accord, j'apporte le dossier bleu",
                "202",
            ],
            ["2030-01-04 18:03:00", "Incoming", "Paul Martin", "Paul Martin", "parfait", "203"],
        ],
    ),
    "Call History": (
        "private\\var\\mobile\\Library\\CallHistoryDB\\CallHistory.storedata",
        ["Timestamp", "Phone Number", "Name", "Call Type", "Duration"],
        [["2030-01-04 17:30:00", "+33600000002", "Paul Martin", "Incoming", "00:01:12"]],
    ),
    "Address Book": (
        "private\\var\\mobile\\Library\\AddressBook\\AddressBook.sqlitedb",
        ["Creation Date", "First Name", "Last Name", "Company", "Phone Numbers", "Email addresses"],
        [
            [
                "2029-12-01 10:00:00",
                "Paul",
                "Martin",
                "Atelier Nord",
                "+33600000002",
                "paul.martin@example.org",
            ]
        ],
    ),
    "Safari Browser - History": (
        "private\\var\\mobile\\Library\\Safari\\History.db",
        ["Visit Timestamp", "Title", "URL", "Visit Count"],
        [
            [
                "2030-01-04 16:00:00",
                "horaires quai 7 - Recherche",
                "https://www.google.com/search?q=horaires+quai+7",
                "1",
            ],
            ["2030-01-04 16:01:00", "Horaires", "https://transports.example.org/horaires", "2"],
        ],
    ),
    "Notes": (
        "private\\var\\mobile\\Containers\\Shared\\AppGroup\\N\\NoteStore.sqlite",
        ["Creation Date", "Title", "Content"],
        [["2030-01-02 12:00:00", "Liste", "acheter un classeur bleu"]],
    ),
    "WiFi Known Networks Times": (
        "private\\var\\preferences\\com.apple.wifi.known-networks.plist",
        ["Last Updated", "SSID", "BSSID", "Last Joined", "Source File"],
        [
            [
                "2030-01-04 08:00:00",
                "Atelier-Nord-WiFi",
                "aa:bb:cc:dd:ee:01",
                "2030-01-04 08:00:00",
                "/private/var/preferences/com.apple.wifi.known-networks.plist",
            ]
        ],
    ),
    "Bluetooth Paired LE": (
        "See Table for Source DB",
        ["UUID", "Name", "Address", "Last Connection Time", "Source File"],
        [
            [
                "U-1",
                "Casque de Camille",
                "11:22:33:44:55:66",
                "2030-01-04 07:00:00",
                "/private/var/containers/Shared/SystemGroup/B/Library/Database/com.apple.MobileBluetooth.ledevices.paired.db",
            ]
        ],
    ),
    "knowledgeC - Device Lock Status": (
        "private\\var\\mobile\\Library\\CoreDuet\\Knowledge\\knowledgeC.db",
        ["Start Time", "End Time", "Time Added", "Device Lock Status"],
        [
            ["2030-01-04 07:00:00", "2030-01-04 07:10:00", "2030-01-04 07:10:00", "Unlocked"],
            ["2030-01-04 23:30:00", "2030-01-05 06:50:00", "2030-01-05 06:50:00", "Locked"],
        ],
    ),
    "Apple Maps Significant Locations Visits (routined)": (
        "private\\var\\mobile\\Library\\Caches\\com.apple.routined\\Local.sqlite",
        [
            "Significant Location Name",
            "Address",
            "City",
            "Latitude",
            "Longitude",
            "Created DateTime",
            "Source File",
        ],
        [
            [
                "Domicile",
                "1 rue du Test",
                "Testville",
                "48.0000",
                "2.0000",
                "2029-12-15 20:00:00",
                "/private/var/mobile/Library/Caches/com.apple.routined/Local.sqlite",
            ]
        ],
    ),
    "Files App - Files stored in iCloud Drive": (
        "private\\var\\mobile\\Library\\Application Support\\CloudDocs\\session\\db\\client.db",
        ["Created", "Modified", "Filename", "Size in bytes"],
        [["2030-01-04 15:00:00", "2030-01-04 15:30:00", "dossier_bleu.pdf", "20480"]],
    ),
    "Gmail - Offline Search": (
        "private\\var\\mobile\\Containers\\Data\\Application\\G\\Library\\Application Support\\data\\x\\searchsqlitedb",
        ["Timestamp", "Sender Name", "Sender Email", "Receiver", "Subject", "Body", "Message ID"],
        [
            [
                "2030-01-04 14:00:00",
                "Atelier Nord",
                "contact@example.org",
                "camille.test@example.org",
                "Votre commande",
                "Votre commande de classeurs est prête.",
                "M-1",
            ]
        ],
    ),
    "InteractionC - Contacts": (
        "private\\var\\mobile\\Library\\CoreDuet\\People\\interactionC.db",
        ["Start Date", "Bundle ID", "Display Name", "Identifier", "Direction"],
        [["2030-01-04 18:00:00", "org.whispersystems.signal", "Paul Martin", "+33600000002", "Incoming"]],
    ),
}


# lignes ajoutées par la variante ambiguë : (artefact, chemin source iOS, en-têtes, lignes)
AMBIGUOUS: dict[str, tuple[str, list[str], list[list[str]]]] = {
    "Signal - Messages": ("", [], [
        ["2030-01-05 20:00:00", "Incoming", "Lucie Bernard", "Lucie Bernard", "si tu me refais le coup du gâteau je te tue 😂", "301"],
        ["2030-01-05 20:01:00", "Outgoing", "", "Lucie Bernard", "promis ! au fait tu me dois 40 balles pour le resto", "302"],
        ["2030-01-05 20:05:00", "Incoming", "Lucie Bernard", "Lucie Bernard", "c'est fait, je t'ai envoyé un Twint", "303"],
        ["2030-01-05 20:06:00", "Outgoing", "", "Lucie Bernard", "efface la photo que je t'ai envoyée, c'était la mauvaise", "304"],
    ]),
    "Gmail - Offline Search": ("", [], [
        ["2030-01-05 18:00:00", "Camille Test", "camille.test@example.org", "camille@atelier-nord.example",
         "Rapport trimestriel", "Je le termine ce soir à la maison. Pièce jointe : rapport_T1.pdf", "M-2"],
    ]),
    "Safari Browser - History": ("", [], [
        ["2030-01-05 21:00:00", "supprimer définitivement des photos iphone - Recherche",
         "https://www.google.com/search?q=supprimer+definitivement+photos+iphone", "1"],
    ]),
    "Wipe Indicators": ("private\\var\\root", ["Timestamp", "Source File", "Source Path"], [
        ["2029-11-30 09:00:00", ".obliterated", "private\\var\\root\\.obliterated"],
    ]),
    "Apps - Historical Combined": ("private\\var\\installd\\Library\\Logs", ["Timestamp", "Event", "Bundle ID", "Event Path"], [
        ["2029-12-01 10:00:00", "Install successful", "org.whispersystems.signal", ""],
        ["2030-01-03 21:00:00", "Uninstalled", "com.example.jeu-de-cartes", ""],
    ]),
}  # fmt: skip


def build_case(root: Path, extra_messages: int = 0, ambiguous: bool = False) -> Path:
    """Écrit le cas synthétique sous `root`. `extra_messages` gonfle Signal (tests d'échelle)."""
    tsv_dir = root / "_TSV Exports"
    tsv_dir.mkdir(parents=True, exist_ok=True)
    lava: dict[str, list[dict]] = {"Synthetic": []}
    artifacts = dict(ARTIFACTS)
    if ambiguous:
        for name, (ios_path, header, rows) in AMBIGUOUS.items():
            base = artifacts.get(name, (ios_path, header, []))
            artifacts[name] = (base[0], base[1], [*base[2], *rows])
    for name, (ios_path, header, rows) in artifacts.items():
        rows = list(rows)
        if name == "Signal - Messages":
            rows += [
                [
                    f"2030-02-{1 + i // 1440 % 28:02d} {i // 60 % 24:02d}:{i % 60:02d}:00",
                    "Incoming",
                    "Paul Martin",
                    "Paul Martin",
                    f"message de remplissage numéro {i}",
                    str(1000 + i),
                ]
                for i in range(extra_messages)
            ]
        with open(tsv_dir / f"{name}.tsv", "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f, delimiter="\t")
            w.writerow(header)
            w.writerows(rows)
        lava["Synthetic"].append(
            {"name": name, "tablename": name.lower(), "record_count": len(rows), "source_path": ios_path}
        )
    (root / "_lava_data.lava").write_text(
        json.dumps(
            {
                "lava_schema_version": 2,
                "parser_info": {"leapp_name": "iLEAPP", "leapp_version": "synthetic"},
                "artifacts": lava,
            }
        ),
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":  # python -m forensic_harness.synthetic_case <dossier> [--ambigu]
    import sys

    print(build_case(Path(sys.argv[1]), ambiguous="--ambigu" in sys.argv[2:]))
