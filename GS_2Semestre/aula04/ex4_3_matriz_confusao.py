"""Exercicio 4.3 - Avaliacao honesta com matriz de confusao (classes desbalanceadas)."""
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)

y_verdadeiro = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1]   # 8 normais, 2 ataques
y_previsto = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]     # o modelo perdeu 1 ataque


def metricas(y_true, y_pred):
    return {
        "matriz": confusion_matrix(y_true, y_pred).tolist(),
        "precisao": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "acuracia": accuracy_score(y_true, y_pred),
    }


if __name__ == "__main__":
    m = metricas(y_verdadeiro, y_previsto)
    print(f"Matriz: {m['matriz']}   # [[VN, FP], [FN, VP]]")
    print(f"Precisão: {m['precisao']:.2f} | Recall: {m['recall']:.2f} | "
          f"F1: {m['f1']:.2f} | Acurácia: {m['acuracia']:.2f}")
    print("""
Interpretação:
- A acurácia de 90% parece boa, mas é inflada pelas 8 amostras normais (classe majoritária).
- O recall de 0,50 mostra que METADE dos ataques reais passou despercebida (1 falso negativo).
- Em um SOC, um ataque não detectado custa muito mais que um alerta falso; por isso, aqui,
  o recall importa mais do que a acurácia (e o F1 ajuda a vigiar o equilíbrio com a precisão).""")
