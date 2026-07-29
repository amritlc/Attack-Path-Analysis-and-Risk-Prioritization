from utils.data_loader import load_access_conditions


def main() -> None:
    access_conditions = load_access_conditions()

    print(
        f"Access conditions loaded: "
        f"{len(access_conditions)}"
    )

    for condition in access_conditions:
        print(
            condition["condition_id"],
            condition["source_asset"],
            "->",
            condition["target_asset"],
            condition["condition_type"],
        )


if __name__ == "__main__":
    main()