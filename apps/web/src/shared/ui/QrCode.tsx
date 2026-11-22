import { useEffect, useState } from 'react';
import { toString } from 'qrcode';

interface QrCodeProps {
  value: string;
  label: string;
  size: number;
}

export function QrCode({ value, label, size }: QrCodeProps) {
  const [image, setImage] = useState<{ value: string; src: string } | null>(null);

  useEffect(() => {
    let active = true;
    toString(value, { type: 'svg', width: size }).then((svg) => {
      if (active) setImage({ value, src: `data:image/svg+xml,${encodeURIComponent(svg)}` });
    }).catch(() => {
      if (active) setImage(null);
    });
    return () => {
      active = false;
    };
  }, [size, value]);

  if (image?.value !== value) return null;

  return <img src={image.src} alt={label} width={size} height={size} className="mx-auto rounded-lg" />;
}
