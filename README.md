# sistema-runner
Repositório dedicado ao desenvolvimento do sistema Runner da disciplina de Implementação e Integração de Software.

#Estrutura geral do Projeto
runner/
├── cli-assinatura/          # CLI em Go
│   ├── cmd/
│   ├── internal/
│   ├── go.mod
│   └── ...
├── assinador/           # Java (assinador.jar)
│   ├── src/
│   ├── pom.xml
│   └── ...
├── cli-simulador/           # CLI em Go (gerencia simulador.jar)
│   ├── cmd/
│   ├── go.mod
│   └── ...
└── .github/
    └── workflows/       # CI/CD + Cosign

    
