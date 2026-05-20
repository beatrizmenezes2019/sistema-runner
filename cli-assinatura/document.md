## 💻 Interface de Linha de Comando (CLI em Go)

Para eliminar a necessidade de digitar comandos complexos do Java manualmente, o projeto disponibiliza uma CLI desenvolvida em **Go**. Ela funciona como um *wrapper* nativo de alta performance que gerencia os parâmetros, valida o ambiente e invoca o `assinador.jar` nos bastidores.

### 🗂️ Estrutura de Distribuição Esperada
Para que os comandos da CLI funcionem localmente no **Modo Local (Sprint 2)**, o executável compilado e o arquivo compactado Java devem estar no mesmo diretório:

```text
📂 seu-diretorio/
├── 📄 assinatura-windows.exe (ou assinatura-linux / assinatura-macos)
└── 📄 assinador.jar
```

### 🚀 Como Executar os Comandos via CLI
### A. Gerar Assinatura Digital (sign)
O comando sign encapsula os 7 parâmetros exigidos pelo núcleo criptográfico do assinador.

```Bash
# Exemplo de execução no Windows
./assinatura-windows.exe sign \
  "C:\teste\arquivos\bundle.json" \
  "C:\teste\arquivos\provenance.json" \
  "{\"PKCS12\":{\"Conteúdo\":\"C:\\teste\\arquivos\\certificado.p12\",\"Senha\":\"senha123\",\"Alias\":\"assinador-teste\"}}" \
  "C:\teste\arquivos\certificado.cer" \
  1751328000 \
  "iat" \
  "[https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca](https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca)|0.0.2"
```
Validação Automática: A CLI em Go valida se todos os 7 argumentos foram informados antes de disparar o processo Java. Caso falte algum parâmetro, a execução é interrompida imediatamente com uma mensagem orientativa.

### B. Validar Assinatura Existente (validate)
O comando validate recebe o JWS bruto (ou o envelope de diagnóstico) e a estrutura de chaves confiáveis.

```Bash
./assinatura-windows.exe validate \
  "INTEGRAL_JWS_STRING_AQUI" \
  "{\"trustStore\":[\"hash_sha256_da_raiz\"]}"
```

### C. Verificar Versão da Aplicação (version)
Exibe a versão semântica atualizada do ecossistema de compilação da CLI.

```Bash
./assinatura-windows.exe version
# Saída esperada: Sistema Runner CLI Assinatura - Versão: 0.1.0
```

### 🛡️ Tratamento de Erros Integrado na CLI
A CLI intercepta falhas de infraestrutura comuns antes que elas afetem a aplicação, exibindo saídas limpas no terminal:

1. JAR Ausente: Se o assinador.jar não for encontrado na mesma pasta, o Go retorna:
```Bash
Erro: assinador.jar não encontrado no diretório atual.
```
2. Ambiente Sem Java: Se a máquina de execução não possuir o comando java configurado no PATH do sistema, o Go captura a falha e avisa o usuário (requisito que será automatizado pelo provisionador na US-04.1).

3. Mapeamento de Fluxo: Todo o retorno gerado pelo Java (incluindo o JSON OperationOutcome padrão FHIR) é canalizado em tempo real e impresso diretamente no console do terminal onde o usuário digitou o comando.