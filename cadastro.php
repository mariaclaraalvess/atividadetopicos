<?php
// Conectar ao banco de dados
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "atvd_db"; // Substitua por o nome do banco de dados que você criou

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
  die("Falha na conexão: " . $conn->connect_error);
}

// Função para validar e higienizar entradas
function limparEntrada($dados) {
  $dados = trim($dados);
  $dados = stripslashes($dados);
  $dados = htmlspecialchars($dados);
  return $dados;
}

// Verificar se o formulário foi enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  $nome = limparEntrada($_POST['nome']);
  $email = limparEntrada($_POST['email']);
  $senha = limparEntrada($_POST['senha']);
  $confirma_senha = limparEntrada($_POST['confirma_senha']);
  $termos = isset($_POST['termos']) ? true : false;

  // Validar se as senhas coincidem
  if ($senha !== $confirma_senha) {
    echo "As senhas não coincidem!";
    exit();
  }

  // Validar e verificar se o e-mail já está cadastrado
  $stmt = $conn->prepare("SELECT id FROM usuarios WHERE email = ?");
  $stmt->bind_param("s", $email);
  $stmt->execute();
  $stmt->store_result();

  if ($stmt->num_rows > 0) {
    echo "E-mail já está em uso!";
    exit();
  }

  // Gerar o hash da senha usando bcrypt
  $hash_senha = password_hash($senha, PASSWORD_BCRYPT);

  // Inserir o novo usuário no banco de dados
  $stmt = $conn->prepare("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)");
  $stmt->bind_param("sss", $nome, $email, $hash_senha);

  if ($stmt->execute()) {
    echo "Cadastro realizado com sucesso!";
  } else {
    echo "Erro ao cadastrar: " . $stmt->error;
  }

  $stmt->close();
}

$conn->close();
?>
