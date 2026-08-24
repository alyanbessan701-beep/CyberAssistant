import librosa
import numpy as np

def extract_mel_spectrogram(file_path: str, max_pad_len: int = 174) -> np.ndarray:
    try:
        audio, sample_rate = librosa.load(file_path, res_type='kaiser_fast', duration=3)
        mel_spectrogram = librosa.feature.melspectrogram(y=audio, sr=sample_rate, n_mels=40)

        if mel_spectrogram.shape[1] < max_pad_len:
            pad_width = max_pad_len - mel_spectrogram.shape[1]
            mel_spectrogram = np.pad(mel_spectrogram, pad_width=((0, 0), (0, pad_width)), mode='constant')
        else:
            mel_spectrogram = mel_spectrogram[:, :max_pad_len]

        return mel_spectrogram
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None