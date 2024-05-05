def calculate_transaction_fees(transactions):
  transaction_fees = []
  for transaction in transactions:
    inputs = transaction.get('vin', [])
    outputs = transaction.get('vout', [])

    total_input_value = sum(input.get('prevout', {}).get('value', 0) for input in inputs)

    total_output_value = sum(output.get('value', 0) for output in outputs)

    fee = total_input_value - total_output_value
    transaction_fees.append((transaction, fee))
  
  transaction_fees.sort(key=lambda x: x[1], reverse=True)
  return transaction_fees