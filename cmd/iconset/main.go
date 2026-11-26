// Command iconset generates Android launcher icons from a source image:
// center-crop to square and resize to all mipmap densities.
package main

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"

	"golang.org/x/image/draw"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: iconset <src image> <android res dir>")
		os.Exit(1)
	}
	srcPath, resDir := os.Args[1], os.Args[2]

	f, err := os.Open(srcPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	src, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Center square crop.
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	side := min(w, h)
	x0 := b.Min.X + (w-side)/2
	y0 := b.Min.Y + (h-side)/2
	square := image.Rect(x0, y0, x0+side, y0+side)

	sizes := map[string]int{
		"mipmap-mdpi":    48,
		"mipmap-hdpi":    72,
		"mipmap-xhdpi":   96,
		"mipmap-xxhdpi":  144,
		"mipmap-xxxhdpi": 192,
	}
	for dir, size := range sizes {
		dst := image.NewRGBA(image.Rect(0, 0, size, size))
		draw.CatmullRom.Scale(dst, dst.Bounds(), src, square, draw.Over, nil)
		outDir := filepath.Join(resDir, dir)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out := filepath.Join(outDir, "ic_launcher.png")
		of, err := os.Create(out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := png.Encode(of, dst); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		of.Close()
		fmt.Println(out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
