#!/usr/bin/env python3
"""
Create a simple icon for the IDS DSL Engine
"""

try:
    from PIL import Image, ImageDraw, ImageFont
    import os
    
    # Create icon directory
    os.makedirs('web_interface', exist_ok=True)
    
    # Create a 64x64 icon
    size = 64
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw shield background
    draw.ellipse([8, 8, size-8, size-8], fill=(102, 126, 234, 255), outline=(255, 255, 255, 255), width=2)
    
    # Draw shield shape
    shield_points = [
        (size//2, 12),  # Top
        (size-12, 20),  # Right
        (size-12, size-20),  # Right bottom
        (size//2, size-8),  # Bottom center
        (12, size-20),  # Left bottom
        (12, 20)  # Left
    ]
    draw.polygon(shield_points, fill=(255, 255, 255, 255))
    
    # Draw "IDS" text
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 12)
    except:
        font = ImageFont.load_default()
    
    text = "IDS"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (size - text_width) // 2
    y = (size - text_height) // 2 - 2
    
    draw.text((x, y), text, fill=(102, 126, 234, 255), font=font)
    
    # Save the icon
    img.save('web_interface/icon.png')
    print("✅ Icon created successfully!")
    
except ImportError:
    print("⚠️  PIL not available, creating a simple text icon...")
    
    # Create a simple text-based icon
    with open('web_interface/icon.txt', 'w') as f:
        f.write("""
    🛡️ IDS DSL Engine
    ================
    
    Smart Network Security System
    """)
    
    print("✅ Text icon created!")
    
except Exception as e:
    print(f"⚠️  Could not create icon: {e}")
    print("The application will work without an icon.")
