-- Exercicio 1.2 - CRUD SQL completo sobre a tabela alertas

DROP TABLE IF EXISTS alertas;
CREATE TABLE alertas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo VARCHAR(50), ip_origem VARCHAR(45),
    severidade ENUM('baixa','media','alta','critica'),
    status VARCHAR(20) DEFAULT 'aberto',
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- (a) inserir 3 alertas (+1 antigo, com 120 dias, para o item (e))
INSERT INTO alertas (tipo, ip_origem, severidade) VALUES
    ('BRUTE_FORCE', '185.220.101.1',  'critica'),
    ('PORT_SCAN',   '91.240.118.172', 'alta'),
    ('XSS',         '45.33.32.156',   'alta');
INSERT INTO alertas (tipo, ip_origem, severidade, criado_em) VALUES
    ('WP_ADMIN', '45.33.32.156', 'media', NOW() - INTERVAL 120 DAY);

-- (b) listar apenas os de severidade 'alta'
SELECT * FROM alertas WHERE severidade = 'alta';

-- (c) atualizar um alerta para 'resolvido'
UPDATE alertas SET status = 'resolvido' WHERE tipo = 'PORT_SCAN';

-- (d) contar alertas por severidade
SELECT severidade, COUNT(*) AS total
FROM alertas
GROUP BY severidade
ORDER BY total DESC;
-- severidade | total
-- alta       | 2
-- critica    | 1
-- media      | 1

-- (e) apagar alertas com mais de 90 dias
DELETE FROM alertas WHERE criado_em < NOW() - INTERVAL 90 DAY;
SELECT COUNT(*) AS restantes FROM alertas;   -- 3
