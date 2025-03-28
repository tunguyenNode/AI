<?php

namespace App\Helpers;

use Cake\Log\Log;
use Exception;

/**
 * 在留カードの署名検証を行うサービス
 */
class ResidenceCardValidationService
{
    /**
     * openssl実行ファイルのパス（設定可能）
     * @var string
     */
    private $opensslExec = 'openssl';

    /**
     * クリーンアップ用の一時ファイルリスト
     * @var array
     */
    private $tempFiles = [];

    /**
     * デストラクタ：スクリプト終了時に一時ファイルを確実にクリーンアップする
     */
    public function __destruct()
    {
        $this->cleanupTempFiles();
    }

    /**
     * 在留カードデータの署名を検証します。
     * このメソッドは、各ファイルの生のバイナリデータを入力として受け取ります。
     *
     * @param string $df3_ef01_binary DF3/EF01 のバイナリデータ (チェックコードと証明書を含むTLV)
     * @param string $df1_ef01_binary DF1/EF01 のバイナリデータ (券面(表)イメージ)
     * @param string $df1_ef02_binary DF1/EF02 のバイナリデータ (顔画像)
     * @return bool 署名が有効な場合はtrue、それ以外はfalse。
     */
    public function verifySignature(
        string $df3_ef01_binary,
        string $df1_ef01_binary,
        string $df1_ef02_binary
    ): bool
    {
        $this->tempFiles = []; // 今回の実行用の一時ファイルリストをリセット
        $is_signature_valid = false;
        $df3_ef01_binary = hex2bin($df3_ef01_binary);
        $df1_ef01_binary = hex2bin($df1_ef01_binary);
        $df1_ef02_binary = hex2bin($df1_ef02_binary);
        try {
            Log::info('署名検証プロセスを開始...', ['scope' => 'ResidenceCardValidation']);

            // --- 入力データの長さチェック ---
            $imageDataFront_bytes = $df1_ef01_binary;
            $imageDataFace_bytes = $df1_ef02_binary;


            // --- DF3/EF01 データを解析して署名と証明書を取得 ---
            Log::debug('DF3/EF01 データを解析中...', ['scope' => 'ResidenceCardValidation']);

            $parsedTlv = $this->parseDf3Ef01Data($df3_ef01_binary);
            Log::debug('DF3/EF01 データを解析中...', ['scope' => $parsedTlv]);

            Log::debug('DF3/EF01 データを解析中...', ['scope' => 'ResidenceCardValidation']);
            $signature_bytes = hex2bin($parsedTlv['check_code_hex']); // Binary data
            $cert_bytes_der = hex2bin($parsedTlv['cert_hex']);     // Binary data
            Log::debug('DF3/EF01 の解析完了。チェックコード (' . strlen($signature_bytes) . 'B), 証明書 (' . strlen($cert_bytes_der) . 'B)', ['scope' => 'ResidenceCardValidation']);


            // --- ステップ①: チェックコード（署名）を復号し、ハッシュを抽出 ---
            Log::info('ステップ①: チェックコード（署名）を復号し、ハッシュを抽出', ['scope' => 'ResidenceCardValidation']);
            // performStep1は、今、バイナリデータを直接受信します。
            $extracted_hash_bytes = $this->performStep1($signature_bytes, $cert_bytes_der);

            Log::info('署名からのSHA-256ハッシュの抽出に成功。', ['scope' => 'ResidenceCardValidation']);
            Log::debug('抽出されたハッシュ（16進）: ' . strtoupper(bin2hex($extracted_hash_bytes)), ['scope' => 'ResidenceCardValidation']);


            // --- ステップ②: 画像データを連結 ---
            Log::info('ステップ②: 画像データを連結', ['scope' => 'ResidenceCardValidation']);
            $concatenatedData = $imageDataFront_bytes . $imageDataFace_bytes; // Sử dụng dữ liệu binary đầu vào
            if (strlen($concatenatedData) !== 10000) {
                throw new Exception("内部エラー: 連結データの長さが10000バイトではありません。");
            }
            Log::info('画像データの連結成功 (10000 バイト)。', ['scope' => 'ResidenceCardValidation']);


            // --- ステップ③: 連結データのSHA-256ハッシュを計算 ---
            Log::info('ステップ③: 連結データのSHA-256ハッシュを計算', ['scope' => 'ResidenceCardValidation']);
            $calculated_hash_bytes = hash('sha256', $concatenatedData, true);
            if ($calculated_hash_bytes === false || strlen($calculated_hash_bytes) !== 32) {
                throw new Exception("連結データのSHA-256ハッシュを計算できませんでした。");
            }
            Log::info('連結データのSHA-256ハッシュの計算に成功。', ['scope' => 'ResidenceCardValidation']);
            Log::debug('計算されたハッシュ（16進）: ' . strtoupper(bin2hex($calculated_hash_bytes)), ['scope' => 'ResidenceCardValidation']);


            // --- ステップ④: 2つのハッシュ値を比較 ---
            Log::info('ステップ④: 2つのハッシュ値を比較', ['scope' => 'ResidenceCardValidation']);
            if ($extracted_hash_bytes === $calculated_hash_bytes) {
                Log::info('結果: 署名は有効です！', ['scope' => 'ResidenceCardValidation']);
                $is_signature_valid = true;
            } else {
                Log::warning('結果: 署名は無効です！', ['scope' => 'ResidenceCardValidation']);
                $is_signature_valid = false;
            }

        } catch (Exception $e) {
            Log::error('署名検証プロセス中にエラーが発生しました: ' . $e->getMessage(), [
                'scope' => 'ResidenceCardValidation',
                'exception' => $e
            ]);
            $is_signature_valid = false;
        } finally {
            $this->cleanupTempFiles();
        }

        return $is_signature_valid;
    }



    /**
     * DF3/EF01のバイナリデータを解析し、チェックコードと公開鍵証明書のバイナリデータを抽出します。
     * TLV構造を解析します（証明書の可変長に対応）。
     *
     * @param string $df3_ef01_binary_data DF3/EF01から読み取った生のバイナリデータ。
     * @return array ['check_code_bytes' => string, 'cert_bytes' => string] 形式の連想配列。
     * @throws Exception 解析に失敗した場合。
     */
    private function parseDf3Ef01Data(string $df3_ef01_binary_data): array
    {
        $offset = 0;
        $check_code_hex = null;
        $cert_hex = null;
        $total_len = strlen($df3_ef01_binary_data);

        // -- タグDA（チェックコード）の分析---

        if ($offset >= $total_len || $df3_ef01_binary_data[$offset] !== "\xDA")
            throw new Exception('...');
        $offset++;
        if ($offset >= $total_len || $df3_ef01_binary_data[$offset] !== "\x82")
            throw new Exception('...');
        $offset++;
        if ($offset + 1 >= $total_len) throw new Exception('...');
        $len_high = ord($df3_ef01_binary_data[$offset++]);
        $len_low = ord($df3_ef01_binary_data[$offset++]);
        $check_code_len = ($len_high << 8) + $len_low;
        if ($check_code_len !== 256) throw new Exception('...');
        if ($offset + $check_code_len > $total_len) throw new Exception('...');
        $check_code_value_bytes = substr($df3_ef01_binary_data, $offset, $check_code_len);
        $check_code_hex = bin2hex($check_code_value_bytes);
        $offset += $check_code_len;

        // --- タグDB（証明書）の分析 ---
        if ($offset >= $total_len || $df3_ef01_binary_data[$offset] !== "\xDB") throw new Exception('...');
        $offset++;
        if ($offset >= $total_len || $df3_ef01_binary_data[$offset] !== "\x82") throw new Exception('...');
        $offset++;
        if ($offset + 1 >= $total_len) throw new Exception('...');
        $len_high = ord($df3_ef01_binary_data[$offset++]);
        $len_low = ord($df3_ef01_binary_data[$offset++]);
        $cert_len = ($len_high << 8) + $len_low;
        if ($cert_len <= 0) throw new Exception('...');
        if ($offset + $cert_len > $total_len) throw new Exception('...');
        $cert_value_bytes = substr($df3_ef01_binary_data, $offset, $cert_len);
        $cert_hex = bin2hex($cert_value_bytes);
        $offset += $cert_len;

        return ['check_code_hex' => $check_code_hex, 'cert_hex' => $cert_hex];
    }



    /**
     * ステップ①を実行: opensslコマンドを使用して署名を復号し、ハッシュを抽出します。
     * @param string $signature_bytes 署名のバイナリデータ
     * @param string $cert_bytes_der 証明書のDER形式バイナリデータ
     * @return string 抽出された32バイトのバイナリハッシュ
     * @throws Exception 失敗した場合
     */
    private function performStep1(string $signature_bytes, string $cert_bytes_der): string
    {
        $pubkey_pem_file = tempnam("/tmp", 'rcv_pubkey_'. $this->uuidv4()) . '.pem';
        $signature_file = tempnam("/tmp", 'rcv_sig_'.$this->uuidv4()) . '.bin';
        $decrypted_file = tempnam("/tmp", 'rcv_dec_'.$this->uuidv4()) . '.bin';

        // 生成したファイル名をクリーンアップリストに追加
        // array_pushでは既存のキーを上書きしないため、$this->tempFilesに直接代入する
        $this->tempFiles = [$pubkey_pem_file, $signature_file, $decrypted_file];

        // 1a. DER証明書から公開鍵(PEM形式)を抽出
        // Log::debug('Step 1a: 公開鍵を抽出中...', ['scope' => 'ResidenceCardValidation']);
        $cmd_extract = $this->opensslExec . " x509 -inform der -pubkey -noout";
        list($ret_extract, $pubkey_pem_str, $err_extract) = $this->runCommand($cmd_extract, $cert_bytes_der);
        if ($ret_extract != 0 || empty($pubkey_pem_str) || strpos($pubkey_pem_str, '-----BEGIN PUBLIC KEY-----') === false) {
            $errorDetails = !empty($err_extract) ? trim($err_extract) : 'OpenSSLからの出力が無効または空です。';
            if (strpos($err_extract ?? '', 'asn1_item_embed_d2i:field missing') !== false) {
                $errorDetails .= " (ASN.1エラー 'field missing' は証明書DERデータに問題があることを示唆しています)";
            }
            throw new Exception("公開鍵を抽出できませんでした。OpenSSLエラー: " . $errorDetails);
        }
        if (file_put_contents($pubkey_pem_file, $pubkey_pem_str) === false) {
            throw new Exception("公開鍵を一時ファイルに書き込めませんでした: " . $pubkey_pem_file);
        }
        // Log::debug('Step 1a: 公開鍵の抽出と保存に成功。', ['scope' => 'ResidenceCardValidation']);

        // 1b. 署名データを一時ファイルに保存
        if (file_put_contents($signature_file, $signature_bytes) === false) {
            throw new Exception("署名を一時ファイルに書き込めませんでした: " . $signature_file);
        }
        // Log::debug('Step 1b: 署名を一時ファイルに保存成功。', ['scope' => 'ResidenceCardValidation']);

        // 1c. openssl rsautl を使用して署名を復号
        // Log::debug('Step 1c: 署名を復号中...', ['scope' => 'ResidenceCardValidation']);
        $cmd_decrypt_file = $this->opensslExec . " rsautl -verify -in " . escapeshellarg($signature_file) .
            " -inkey " . escapeshellarg($pubkey_pem_file) . " -pubin -pkcs -out " . escapeshellarg($decrypted_file);
        list($ret_decrypt_file, $out_decrypt, $err_decrypt) = $this->runCommand($cmd_decrypt_file);
        if ($ret_decrypt_file != 0) {
            throw new Exception("署名の復号に失敗しました。OpenSSLエラー: " . trim($err_decrypt));
        }
        // Log::debug('Step 1c: 署名の復号成功。', ['scope' => 'ResidenceCardValidation']);

        // 1d. 復号されたデータ（DigestInfoのはず）を読み込み、ハッシュを抽出
        $decrypted_data = file_get_contents($decrypted_file);
        if ($decrypted_data === false) {
            throw new Exception("復号結果を一時ファイルから読み込めませんでした: " . $decrypted_file);
        }
        // Log::debug('Step 1d: 復号データの読み込み成功 (' . strlen($decrypted_data) . ' バイト)。', ['scope' => 'ResidenceCardValidation']);

        $extracted_hash = $this->extractSha256FromDigestInfo($decrypted_data);
        if ($extracted_hash === false) {
            // エラーは extractSha256FromDigestInfo 内でログ記録される
            throw new Exception("復号されたデータからSHA-256ハッシュを抽出できませんでした。");
        }

        return $extracted_hash;
    }

    /**
     * proc_openを使用して外部コマンドを実行します。
     * @param string $cmd 実行するコマンド文字列。
     * @param string|null $stdin_data 標準入力に渡すデータ（バイナリ可）。
     * @return array [終了コード, 標準出力文字列, 標準エラー出力文字列]
     */
    private function runCommand(string $cmd, ?string $stdin_data = null): array
    {
        $descriptorSpec = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
        $pipes = [];
        $stdout = '';
        $stderr = '';
        $return_value = -1;
        // Log::debug("コマンド実行: {$cmd}", ['scope' => 'ResidenceCardValidation.Command']);
        $process = proc_open($cmd, $descriptorSpec, $pipes);
        if (is_resource($process)) {
            if ($stdin_data !== null) {
                fwrite($pipes[0], $stdin_data);
            }
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            $return_value = proc_close($process);
            // Log::debug("Cmd exit code:{$return_value}, stdout:" . (empty($stdout)?'empty':strlen($stdout).'B') .", stderr:" . (empty($stderr)?'empty':strlen($stderr).'B'), ['scope' => 'ResidenceCardValidation.Command']);
        } else {
            $stderr = 'プロセスを開けませんでした: ' . $cmd;
            Log::error($stderr, ['scope' => 'ResidenceCardValidation.Command']);
        }
        return [$return_value, $stdout, $stderr];
    }

    /**
     * SHA-256のASN.1 DER DigestInfo構造を解析し、ハッシュ値を抽出します。
     * @param string $decrypted_data 復号されたバイナリデータ（ステップ1の結果）。
     * @return string|false 成功した場合は32バイトのバイナリハッシュ、失敗した場合はfalse。
     */
    private function extractSha256FromDigestInfo(string $decrypted_data)
    {
        $expected_prefix_hex = "3031300D060960864801650304020105000420";
        $prefix_len = strlen(hex2bin($expected_prefix_hex));
        $hash_len = 32;
        if (strlen($decrypted_data) === $prefix_len + $hash_len) {
            $prefix_bytes = substr($decrypted_data, 0, $prefix_len);
            if (strtoupper(bin2hex($prefix_bytes)) === $expected_prefix_hex) {
                return substr($decrypted_data, $prefix_len);
            }
        }
        Log::error("復号されたデータが期待されるSHA-256 DigestInfo構造と一致しません。", [
            'scope' => 'ResidenceCardValidation',
            'data_hex' => strtoupper(bin2hex($decrypted_data))
        ]);
        return false;
    }

    /**
     * 検証中に作成された一時ファイルをクリーンアップします。
     */
    private function cleanupTempFiles(): void
    {
        // Log::debug('一時ファイルをクリーンアップ中...', ['scope' => 'ResidenceCardValidation']);
        foreach ($this->tempFiles as $file) {
            if (!empty($file) && file_exists($file)) {
                if (!@unlink($file)) { // エラー抑制演算子を使用
                    Log::warning("一時ファイルを削除できませんでした: {$file}", ['scope' => 'ResidenceCardValidation']);
                }
            }
        }
        $this->tempFiles = []; // リストをクリア
    }

    function uuidv4()
    {
        $data = random_bytes(16);

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
