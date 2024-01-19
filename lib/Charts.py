from collections import Counter


class Charts:
    def extract_indicators_percentages(self,data):
        attack_results = []
        for attack in data:
            attack_name = attack["attack_name"]

            # Extract indicators and their types from the attack
            indicators = [(ioc["indicator"], ioc["type"]) for ioc in attack["IOCs"]]

            # Count the occurrences of each indicator type
            indicator_type_counter = Counter(indicator[1] for indicator in indicators)

            # Calculate percentages
            total_indicators = len(indicators)
            indicator_type_percentages = {indicator_type: round(count / total_indicators * 100, 2) for
                                          indicator_type, count in indicator_type_counter.items()}

            # Append the results to the list
            attack_results.append({attack_name: indicator_type_percentages})

        return attack_results



