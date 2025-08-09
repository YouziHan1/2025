
import cv2
import numpy as np
import pywt
import os

class Watermark:
    def __init__(self, alpha=0.1):
        self.alpha = alpha

    def _embed_dwt_svd(self, original_coeffs, watermark_coeffs):
        U, S, V = np.linalg.svd(original_coeffs[0])
        w_U, w_S, w_V = np.linalg.svd(watermark_coeffs[0])
        
        w_S_padded = np.zeros_like(S)
        w_S_padded[:len(w_S)] = w_S

        S_new = S + self.alpha * w_S_padded
        
        h, w = original_coeffs[0].shape
        sigma_new = np.zeros((h, w))
        for i in range(len(S_new)):
            sigma_new[i, i] = S_new[i]
            
        coeffs_embedded = U @ sigma_new @ V
        return (coeffs_embedded, original_coeffs[1])

    def _extract_dwt_svd(self, watermarked_coeffs, original_coeffs, watermark_LL_original):
        #提取
        U_wm, S_wm, V_wm = np.linalg.svd(watermarked_coeffs[0])
        U_orig, S_orig, V_orig = np.linalg.svd(original_coeffs[0])
        
        # 提取水印的奇异值
        S_extracted_padded = (S_wm - S_orig) / self.alpha
        
        # 获取原始水印LL子带的SVD分解和尺寸
        w_U, _, w_V = np.linalg.svd(watermark_LL_original)
        h, w = watermark_LL_original.shape
        
        # 创建sigma矩阵重构水印
        w_sigma_extracted = np.zeros((h, w))
        
        diag_len = min(h, w, len(S_extracted_padded))
        for i in range(diag_len):
            w_sigma_extracted[i, i] = S_extracted_padded[i]

        watermark_coeffs_LL = w_U @ w_sigma_extracted @ w_V
        return watermark_coeffs_LL


    def embed(self, original_image_path, watermark_image_path, output_path):
        # 水印嵌入
        original_img = cv2.imread(original_image_path, cv2.IMREAD_COLOR)
        h, w, _ = original_img.shape
        original_img_yuv = cv2.cvtColor(original_img, cv2.COLOR_BGR2YUV)
        original_y = original_img_yuv[:, :, 0]

        watermark_img = cv2.imread(watermark_image_path, cv2.IMREAD_GRAYSCALE)
        watermark_img_resized = cv2.resize(watermark_img, (w // 2, h // 2)) # 稍微增大了水印尺寸以获得更稳定的SVD

        original_coeffs = pywt.dwt2(original_y, 'haar')
        watermark_coeffs = pywt.dwt2(watermark_img_resized, 'haar')

        embedded_coeffs = self._embed_dwt_svd(original_coeffs, watermark_coeffs)

        embedded_y = pywt.idwt2(embedded_coeffs, 'haar')
        embedded_y = cv2.resize(embedded_y, (w, h))

        final_img_yuv = original_img_yuv.copy()
        final_img_yuv[:, :, 0] = embedded_y.astype('uint8')
        final_img = cv2.cvtColor(final_img_yuv, cv2.COLOR_YUV2BGR)

        cv2.imwrite(output_path, final_img)
        print(f"水印已嵌入并保存至: {output_path}")
        return final_img

    def extract(self, watermarked_image_path, original_image_path, original_watermark_path, output_path, extracted_size=(128, 128)):
        # 水印提取
        original_img = cv2.imread(original_image_path)
        orig_h, orig_w, _ = original_img.shape
        
        watermarked_img = cv2.imread(watermarked_image_path)

        wm_h, wm_w, _ = watermarked_img.shape
        if (wm_h, wm_w) != (orig_h, orig_w):
            watermarked_img = cv2.resize(watermarked_img, (orig_w, orig_h))

        original_yuv = cv2.cvtColor(original_img, cv2.COLOR_BGR2YUV)
        original_y = original_yuv[:, :, 0]
        
        original_watermark_img = cv2.imread(original_watermark_path, cv2.IMREAD_GRAYSCALE)
        original_watermark_resized = cv2.resize(original_watermark_img, (orig_w // 2, orig_h // 2))
        
        watermarked_coeffs = pywt.dwt2(cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YUV)[:,:,0], 'haar')
        original_coeffs = pywt.dwt2(original_y, 'haar')
        watermark_original_coeffs = pywt.dwt2(original_watermark_resized, 'haar')
        
        extracted_watermark_LL = self._extract_dwt_svd(
            watermarked_coeffs, 
            original_coeffs, 
            watermark_original_coeffs[0]
        )
        
        extracted_watermark_coeffs = (extracted_watermark_LL, watermark_original_coeffs[1])
        extracted_watermark = pywt.idwt2(extracted_watermark_coeffs, 'haar')
        extracted_watermark = cv2.resize(extracted_watermark, extracted_size)

        cv2.normalize(extracted_watermark, extracted_watermark, 0, 255, cv2.NORM_MINMAX)
        extracted_watermark = extracted_watermark.astype('uint8')

        cv2.imwrite(output_path, extracted_watermark)
        return extracted_watermark

def calculate_nc(img1, img2):
    #计算归一化相关系数
    if img1 is None or img2 is None:
        return 0.0
    
    img1 = img1.astype(np.float64)
    img2 = img2.astype(np.float64)

    if img1.shape != img2.shape:
        img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

    numerator = np.sum(img1 * img2)
    denominator = np.sqrt(np.sum(img1**2)) * np.sqrt(np.sum(img2**2))
    
    return 0.0 if denominator == 0 else numerator / denominator

if __name__ == '__main__':
    original_path = 'c:/Users/Savannah/Desktop/2025Creat/2025Creat/PROJECT2/pic.png'
    watermark_path = 'c:/Users/Savannah/Desktop/2025Creat/2025Creat/PROJECT2/logo.jpg'
    embedded_path = 'c:/Users/Savannah/Desktop/2025Creat/2025Creat/PROJECT2/embedded_pic.png'
    extracted_path = 'c:/Users/Savannah/Desktop/2025Creat/2025Creat/PROJECT2/extracted_logo.png'
    
    wm_processor = Watermark(alpha=0.05)
    wm_processor.embed(original_path, watermark_path, embedded_path)
    wm_processor.extract(embedded_path, original_path, watermark_path, extracted_path)
    
    original_watermark = cv2.imread(watermark_path, 0)
    extracted_watermark = cv2.imread(extracted_path, 0)
    
    if extracted_watermark is not None:
        nc_score = calculate_nc(original_watermark, extracted_watermark)
        
        print(f"归一化相关系数: {nc_score:.4f}")
    else:
        print("提取水印失败。")
    
    embedded_img = cv2.imread(embedded_path)
    original_watermark = cv2.imread(watermark_path, 0)
    h, w, _ = embedded_img.shape
    attacks = {
        "no_attack": embedded_img,
        "jpeg_compression_50": embedded_img,
        "gaussian_noise_20": cv2.add(embedded_img, np.random.normal(0, 20, embedded_img.shape).astype('uint8')),
        "flip_horizontal": cv2.flip(embedded_img, 1),
        "contrast_high": cv2.convertScaleAbs(embedded_img, alpha=1.5, beta=0),
        "center_crop_25_percent": embedded_img[h//8:-h//8, w//8:-w//8],
        "rotate_5_deg": cv2.warpAffine(
            embedded_img, 
            cv2.getRotationMatrix2D((w/2, h/2), 5, 1.0), 
            (w, h)
        )
    }

    # 创建目录保存攻击图像
    attacked_dir = "attacked_images"
    if not os.path.exists(attacked_dir):
        os.makedirs(attacked_dir)

    for attack_name, attacked_img_data in attacks.items():
        attacked_img_path = os.path.join(attacked_dir, f"attacked_{attack_name.replace(' ', '_')}.png")
        
        # 对JPEG压缩进行特殊处理
        if "jpeg_compression" in attack_name:
            quality = int(attack_name.split('_')[-1]) 
            cv2.imwrite(attacked_img_path.replace('.png', '.jpg'), attacked_img_data, [cv2.IMWRITE_JPEG_QUALITY, quality])
            attacked_img_path = attacked_img_path.replace('.png', '.jpg') # 更新路径
        else:
            cv2.imwrite(attacked_img_path, attacked_img_data)
        
        # 提取水印
        extracted_path = os.path.join(attacked_dir, f"extracted_{attack_name.replace(' ', '_')}.png")
        extracted_watermark = wm_processor.extract(
            attacked_img_path, 
            original_path, 
            watermark_path, 
            extracted_path
        )
        

        # 计算NC值
        nc_score = calculate_nc(original_watermark, extracted_watermark)
        print(f"攻击类型: {attack_name:<20} | NC值: {nc_score:.4f}")
