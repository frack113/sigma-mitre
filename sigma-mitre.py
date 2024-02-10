import click

from attackcti import attack_client
from sigma.collection import SigmaCollection

from pathlib import Path
import json


def create_references_json():
    data = {}
    lift = attack_client()
    all_techniques = lift.get_techniques()
    print(f"Number of Techniques in ATT&CK {len(all_techniques)}")

    for technique in all_techniques:
        if not technique["revoked"]:
            info = {"score": 0, "description": technique["description"],"rules":[]}
            # find technique sigma tag
            for ref in technique["external_references"]:
                if ref["source_name"] == "mitre-attack":
                    id = str(ref["external_id"])
                    print(f"Find technique {id}")
                    data[id] = info

    print("Save to reference.json")
    with open("reference.json", "w", encoding="UTF-8") as f:
        f.write(json.dumps(data, indent=4, ensure_ascii=False))


def create_heatmap(output_name:str,sigma_data: dict, color1: str, color2: str, color3: str):
    scores = []
    score_max = 0
    for name, data in sigma_data.items():
        if data["score"] > 0:
            metadata = []
            for rule in data["rules"]:
                metadata.append({"name":rule.path.name,"value":str(rule)})

            item = {
                "techniqueID": name,
                "score": data["score"],
                "comment": data["description"],
                "metadata": metadata
            }
            score_max = max(score_max, data["score"])
            scores.append(item)

    output = {
        "name": "Sigma Rules MITRE Heatmap",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Sigma rules heatmap",
        "gradient": {
            "colors": [color1, color2, color3],
            "maxValue": score_max,
            "minValue": 0,
        },
        "techniques": scores,
    }

    with open(output_name, "w", encoding="UTF-8") as f:
        f.write(json.dumps(output, indent=4, ensure_ascii=False))

@click.command()
@click.option(
    "--output-name",
    "-o",
    default="sigma_heatmap.json",
    help="Name of the HeatMap json file",
)
@click.option(
    "--force-update",
    "-f",
    is_flag=True,
    help="Force Internet MITRE update.",
)
@click.option(
    "--color-min",
    "-c1",
    default="#66b1ffff",
    help="Min color '#RRGGBBAA'",
)
@click.option(
    "--color-middle",
    "-c2",
    default="#ff66f4ff",
    help="Middle color '#RRGGBBAA'",
)
@click.option(
    "--color-max",
    "-c3",
    default="#ff6666ff",
    help="Max color '#RRGGBBAA'",
)
@click.option(
    "--color-max",
    "-c3",
    default="#ff6666ff",
    help="Max color '#RRGGBBAA'",
)
@click.argument(
    "input",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, allow_dash=True, path_type=Path),
)
def main(input, output_name,force_update, color_min, color_middle, color_max):
    click.echo("Welcome to Sigma rule Heat Map creator")

    file_missing = False
    if not Path("reference.json").exists():
        click.secho("Missing reference.json", err=True, fg="red")
        file_missing = True
    if file_missing or force_update:
        click.echo("Update the MITRE reference")
        create_references_json()

    click.echo("Load local references")
    with open("reference.json", "r", encoding="UTF-8") as inputfile:
        sigma_data = json.loads(inputfile.read())

    click.echo("Load sigma rules")
    rule_paths = SigmaCollection.resolve_paths(input)
    rule_collection = SigmaCollection.load_ruleset(rule_paths, collect_errors=True)
    for sigmaHQrule in rule_collection:
        for tag in sigmaHQrule.tags:
            if tag.namespace == "attack" and tag.name.startswith("t"):
                if tag.name.upper() in sigma_data:
                    sigma_data[tag.name.upper()]["score"] += 1
                    sigma_data[tag.name.upper()]["rules"].append(sigmaHQrule.source)
                else:
                    click.secho(
                        f"{sigmaHQrule.id} {sigmaHQrule.title} NOT FOUND {tag.name}",
                        err=True,
                        fg="red",
                    )

    create_heatmap(output_name,sigma_data, color_min, color_middle, color_max)


if __name__ == "__main__":
    main()
